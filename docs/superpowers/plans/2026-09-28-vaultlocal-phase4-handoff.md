# VaultLocal — ponto de retomada

**Data:** 2026-09-28
**Branch:** `hardening/phase-1`

Este documento registra o estado do projeto ao final da **Phase 4.2** e serve como handoff para a próxima sessão.

## Estado atual

A autenticação e o acesso rápido foram expandidos até um fluxo WebAuthn/Passkey com PRF, mantendo a arquitetura zero-knowledge.

O stack está publicado localmente em:

```text
http://localhost:8080
```

Para WebAuthn, este é o domínio/origem canônico do ambiente local:

```text
RP ID:   localhost
Origin:  http://localhost:8080
```

O Google OIDC também usa o callback de localhost configurado no ambiente.
## Phase 4.1 — WebAuthn / Passkey

Implementado:

- Registro de passkey com user verification obrigatório.
- Challenge de uso único armazenado no servidor apenas por hash.
- Validação de RP ID, origin, user presence e user verification.
- Contador de assinatura WebAuthn com proteção contra regressão/replay.
- Credencial só se torna confiável depois do envelope da KEK ser gravado.
- PRF WebAuthn usado somente no navegador.
- HKDF-SHA-256 deriva a chave de dispositivo a partir do PRF.
- A KEK bruta de 32 bytes é cifrada localmente com AES-256-GCM.
- O servidor armazena somente o envelope cifrado + nonce.

### Fluxo de desbloqueio rápido

```text
Google (ou identidade local)
        ↓
WebAuthn / Passkey
        ↓
PRF no autenticador
        ↓
HKDF no navegador
        ↓
chave de dispositivo
        ↓
AES-GCM descriptografa envelope
        ↓
KEK em memória
        ↓
cofre descriptografado no cliente
```
## Phase 4.2 — Gestão e login local por passkey

Implementado:

- Login rápido por **e-mail + passkey**, sem depender do Google.
- Login rápido por **Google + passkey** continua funcionando.
- Múltiplas passkeys por usuário.
- Listagem de dispositivos confiáveis.
- Renomeação individual de passkeys.
- Revogação individual de passkeys.
- Revogação protegida por TOTP (step-up).
- Desafios de autenticação local com uso único.
- Credencial revogada deixa de aparecer como dispositivo confiável e não pode mais desbloquear o cofre.
- A senha-mestra continua como fallback.

A tabela `webauthn_credentials` já suportava múltiplas credenciais; não foi necessária uma nova migração para a 4.2.

Migração WebAuthn atual:

```text
009_webauthn_devices (head)
```
## E2E validado no navegador

Foi validado o fluxo real de criação/autenticação de passkey usando **QR Code com o Google Play Services/Android**.

O teste confirmou o cenário cross-device/hybrid WebAuthn: o navegador do computador iniciou a cerimônia e o telefone atuou como autenticador.

Também foi validado:

- criação da credencial;
- conclusão do envelope da KEK em uma segunda interação explícita;
- login posterior com passkey;
- gerenciamento da credencial;
- revogação com TOTP;
- uso do fallback por senha-mestra.

O erro anterior de foco do navegador foi corrigido separando o registro da credencial da cerimônia posterior usada para obter o PRF.

O erro anterior de `invalid WebAuthn registration` também foi corrigido: o challenge persistido pelo backend agora é explicitamente usado ao gerar as opções de registro.
## Validação automatizada

Estado validado ao final da Phase 4.2:

```text
Backend:     106/106 testes ✅
Frontend:     29/29 testes ✅
Ruff:              OK ✅
TypeScript:        OK ✅
Vite build:        OK ✅
git diff --check:  OK ✅
Runtime local:     OK ✅
```

Os novos testes cobrem, entre outros pontos:

- opções de registro;
- registro + envelope;
- isolamento de credenciais não confiáveis;
- login local por passkey;
- consumo único de challenge;
- múltiplos dispositivos;
- renomeação;
- exigência de TOTP para revogação.
## Estado dos dados no momento do handoff

Não apagar dados de teste sem necessidade.

```text
Usuários:                    2
Entradas:                    2
Credenciais WebAuthn:        2
Credenciais confiáveis:      1
Migração Alembic:             009_webauthn_devices
```

Existe backup do banco criado antes das mudanças de infraestrutura/WebAuthn:

```text
backups/vault-20260927-224406.sql.gz
```

Não registrar aqui senha, JWT secret, Client Secret do Google, recovery key, TOTP secret ou qualquer ciphertext real.
## Arquivos importantes adicionados/alterados

Backend:

- `backend/app/models.py` — credenciais e challenges WebAuthn.
- `backend/app/schemas.py` — contratos de WebAuthn e gestão de dispositivos.
- `backend/app/routers/auth.py` — OIDC, WebAuthn, login local e gestão de passkeys.
- `backend/app/webauthn_support.py` — geração/normalização de opções WebAuthn.
- `backend/alembic/versions/008_google_oidc.py` — vínculo Google.
- `backend/alembic/versions/009_webauthn_devices.py` — credenciais/challenges.
- `backend/tests/test_oidc.py`, `test_recovery.py`, `test_webauthn.py`.

Frontend:

- `frontend/src/crypto.ts` — sessão da KEK e material criptográfico.
- `frontend/src/webauthn.ts` — registro, autenticação, PRF e envelope da KEK.
- `frontend/src/pages/Login.tsx` — Google/passkey/login local.
- `frontend/src/pages/Vault.tsx` — ativação e gestão de dispositivos.
- `frontend/src/api.ts` — APIs de WebAuthn.
- `frontend/src/webauthn.test.ts` — testes criptográficos/PRF.
## Próximos passos — Phase 5

### 5.1 Breach Check local

Objetivo: verificar se senhas do cofre aparecem em bases de vazamento sem enviar a senha ou plaintext para um serviço externo.

Direção já planejada:

- processamento 100% client-side;
- download/atualização controlada da base necessária;
- comparação local usando hashes apropriados;
- separar claramente "senha fraca" de "senha conhecida em vazamento";
- não persistir as senhas analisadas no servidor;
- integrar o resultado ao Health Dashboard.

### 5.2 Health Dashboard

Adicionar indicadores de comprometimento ao relatório de saúde existente, mantendo apenas métricas agregadas no backend.

### 5.3 Hardening do ecossistema de passkeys

Depois da Phase 5, considerar:

- suporte a descoberta/resident credentials sem depender da digitação do e-mail, quando fizer sentido;
- melhor identificação de autenticadores;
- confirmação explícita antes de revogar o último dispositivo confiável;
- step-up de TOTP para operações críticas adicionais;
- controles para exportação/importação segura;
- testes E2E de compatibilidade com mais de um navegador/autenticador.
## Antes de continuar o desenvolvimento

1. Não resetar o banco atual.
2. Manter `localhost:8080` como origem de desenvolvimento enquanto o WebAuthn estiver sendo testado.
3. Não voltar para `127.0.0.1:8080` sem revisar RP ID/origin e Google redirect URI.
4. Manter a regra: servidor nunca recebe senha-mestra, KEK, PRF ou segredo em claro.
5. Usar este documento como ponto de retomada e o código atual como source of truth.

## Situação do roadmap

```text
Phase 1  ✅ TOTP
Phase 2  ✅ Recovery / reset
Phase 3  ✅ Google OIDC + E2E
Phase 4.1 ✅ WebAuthn / Passkey + PRF + E2E
Phase 4.2 ✅ Login local + múltiplas passkeys + gestão/revogação
Phase 5.1 ✅ Breach Check HIBP k-anonymity client-side + Health Dashboard
Phase 5.2 ✅ Adapter para índice HIBP offline + 📋 importar/atualizar corpus
```

**Próximo marco recomendado ao retomar:** instalar/atualizar o corpus HIBP local e validar o fluxo E2E com o seletor **Índice local**.
