# VaultLocal — Phase 5.1 Breach Check

**Data:** 2026-09-28  
**Status:** implementada parcialmente: HIBP k-anonymity client-side ✅

## Objetivo

Detectar senhas que aparecem no corpus de Pwned Passwords do Have I Been Pwned sem enviar a senha-mestra, a senha armazenada ou o hash completo para um serviço externo.

## Implementação atual

O navegador:

1. descriptografa as senhas já em memória usando a KEK da sessão;
2. calcula SHA-1 localmente apenas por compatibilidade com o índice Pwned Passwords;
3. agrupa entradas pelos 5 primeiros caracteres do hash;
4. consulta cada prefixo na API de range do HIBP;
5. compara o restante do hash exclusivamente no navegador;
6. descarta os hashes retornados que não correspondem a uma entrada do cofre;
7. mantém somente o resultado mínimo necessário para a UI;
8. envia ao backend apenas o número agregado de entradas afetadas.

A consulta é opt-in pelo botão "Verificar agora". Não acontece automaticamente ao abrir /health.

## Privacidade

O HIBP documenta que Pwned Passwords usa k-anonymity com os primeiros 5 caracteres do SHA-1; o restante do hash e a comparação ficam com o cliente. O serviço também suporta respostas com padding para reduzir vazamento por tamanho da resposta.

O VaultLocal não envia:

- senha em claro;
- hash SHA-1 completo;
- ID da entrada;
- título ou site;
- associação entre uma senha e uma conta VaultLocal.

O backend não recebe os matches detalhados. Ele recebe apenas breached_count.

## Score

O score passa a considerar:

    score = clamp(
      100
      - 20 * breachedCount
      - 15 * weakCount
      - 10 * reusedCount,
      0,
      100
    )

O valor de prevalência retornado pelo HIBP serve para a mensagem detalhada da entrada, mas não é persistido no backend.

## Estado persistido

health_reports.breached_count guarda apenas a contagem agregada da última verificação.

Os detalhes por entrada permanecem somente na memória do navegador. Após reload, eles precisam ser consultados novamente.

## Modo realmente offline

Ainda não está embarcado no produto.

O próprio HIBP mantém um downloader oficial para gerar o corpus completo offline. Esse corpus é grande demais para ser incluído no bundle do VaultLocal ou distribuído junto com o aplicativo.

Próxima etapa:

- índice local/importável;
- atualização incremental;
- armazenamento no cliente;
- pesquisa sem qualquer consulta de senha à internet;
- manter o mesmo contrato do engine para permitir alternar entre provider online e offline.

## Testes

- SHA-1 canônico;
- envio somente do prefixo;
- matching local do suffix;
- deduplicação por prefixo;
- falha de disponibilidade;
- score com breach count;
- persistência agregada no backend.

## E2E pendente

A máquina de desenvolvimento atual não possui resolução DNS para api.pwnedpasswords.com, então a chamada real ao HIBP não foi validada nesta sessão. O restante da integração está coberto por mocks determinísticos.

No navegador com internet, validar:

1. abrir /health;
2. criar uma entrada de teste com uma senha pública conhecida de demonstração;
3. clicar em "Verificar agora";
4. confirmar que a entrada é marcada;
5. abrir DevTools → Network e confirmar que a requisição contém apenas um prefixo de 5 caracteres;
6. confirmar que o request não contém senha ou hash completo;
7. confirmar que o backend registra somente breached_count.

## Próximo marco

**Phase 5.2 — índice HIBP offline importável**, preservando a mesma interface checkPasswords e evitando dependência de rede.
