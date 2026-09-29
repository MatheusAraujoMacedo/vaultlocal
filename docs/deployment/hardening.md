# VaultLocal — Hardening Baseline

Este documento descreve o baseline de segurança do alpha/beta local.
Ele registra controles implementados e limitações conhecidas; não substitui
um pentest, revisão criptográfica ou auditoria independente.

## Controles de aplicação

- Argon2id para autenticação e derivação de material criptográfico.
- AES-256-GCM com envelope encryption por entrada.
- Crypto v2 com AAD ligado ao ID da entrada e aos campos protegidos.
- TOTP obrigatório, secret cifrado em repouso e lockout progressivo.
- Recovery Key com prova ECDSA P-256 e challenge de uso único.
- Access token vinculado a sessão revogável por `sid`.
- Refresh token rotacionado e armazenado somente como hash Argon2id.
- Rate limiting nas superfícies de autenticação e recuperação.
- WebAuthn com user verification, contador e credencial confiável.
- PRF/WebAuthn usado somente no navegador para proteger o envelope da KEK.
- Auto Lock no cliente; a KEK é removida da memória ao bloquear.
- Exportação/importação cifrada processada no navegador.
- Health analysis client-side; backend recebe apenas agregados.
- HIBP online usa k-anonymity; modo offline usa índice local somente leitura.

## Proteções HTTP

- `TrustedHostMiddleware` com allow-list explícita.
- JWT aceita somente o algoritmo configurado e validado como HS256.
- CORS separado para desenvolvimento e produção.
- Security headers no backend e Nginx.
- CSP sem `unsafe-eval`; WASM permitido somente para a necessidade do KDF.
- API marcada como `no-store`/sem cache.
- `X-Frame-Options: DENY`, `nosniff` e `Referrer-Policy: no-referrer`.
## Infraestrutura

- Frontend exposto por padrão somente em `127.0.0.1:8080`.
- API e Postgres não são publicados em portas do host no Compose.
- Corpus HIBP montado no container da API como somente leitura.
- Containers executam sem privilégios desnecessários.
- Secrets de runtime ficam no `.env`, fora do Git.
- OpenAPI/ReDoc ficam desabilitados em produção.

## Integridade do cliente

O modelo zero-knowledge protege os dados armazenados, mas não transforma
um navegador comprometido em um ambiente confiável. Um servidor ou artefato
frontend adulterado pode capturar uma senha-mestra durante o uso. Por isso,
CSP, integridade do build, controle de dependências e o deploy são partes
do modelo de ameaça.

## Limitações aceitas no alpha

O produto é local-first e ainda não possui uma auditoria externa. O rate
limiter atual é adequado ao processo local, mas não é um mecanismo distribuído
para múltiplas instâncias. A busca por `title`/`site` expõe esses metadados
ao backend por decisão arquitetural documentada. O export temporariamente
descriptografa o conteúdo na memória do navegador para gerar o novo envelope.

## Validação

Antes de uma release de alpha/beta, executar:

```bash
make test
make test-frontend
cd frontend && npm run build && npx tsc --noEmit
cd ../backend && ../.venv/bin/ruff check app tests
git diff --check
make migrate
```

Também validar o fluxo E2E de login, TOTP, recovery, passkey, criação de entrada,
export/import, auto lock, timeline e HIBP local.

## Regra para deploy público

Não reutilizar secrets do ambiente local. Trocar domínio, origins, cookies,
CSP, allow-list de hosts e política de armazenamento antes de qualquer
exposição fora da máquina local.
