# RFC: Autenticação forte e recuperação de acesso (v2)

- Status: Proposta (v2 — revisada)
- Data: 2026-09-23
- Autor: Matheus (revisão técnica assistida)
- Substitui: RFC v1 (2026-09-23)

## 1. Resumo executivo

O VaultLocal adota **três camadas de autenticação obrigatórias**, mesmo em
deploy local-first:

1. **Identidade** — Google OIDC (login social) ou email + senha-mestra local.
2. **Segundo fator** — TOTP obrigatório (Google Authenticator, Authy, etc.).
3. **Dispositivo confiável** — WebAuthn/passkey com biometria quando o
   navegador/OS suportar; TOTP como fallback manual.

O "Esqueci minha senha" é um **reset criptográfico de emergência**, nunca uma
recuperação da senha antiga. Toda a criptografia permanece **E2E e
zero-knowledge**: o servidor nunca vê senha-mestra, KEK, recovery key ou
plaintext dos segredos — apenas blobs opacos, `auth_hash`, TOTP secret e
credenciais WebAuthn (chaves públicas).

**Núcleo da solução de recuperação:** a senha-mestra esquecida é
irrecuperável *por construção* (zero-knowledge). Por isso a conta nasce com
uma **recovery key obrigatória** (32 bytes, exibida uma única vez no
onboarding). Só ela garante reset **sem perda do cofre**. O reset por email
existe como fallback destrutivo (nova conta, cofre antigo apagado), para
quem perdeu senha **e** recovery key.

## 2. Princípios inegociáveis

| # | Princípio |
|---|-----------|
| P1 | Servidor nunca recebe senha-mestra, KEK, data_key, recovery key ou plaintext. |
| P2 | Google é **identidade de acesso**, nunca chave do cofre. Mesmo logado com Google, a senha-mestra continua existindo e é obrigatória para desbloquear o cofre. |
| P3 | Login completo exige identidade + TOTP (+ WebAuthn quando disponível). Sem as 3 camadas configuradas, o cofre não abre. |
| P4 | "Recuperar senha" no sentido clássico é impossível. O que existe é *reset com recovery key* (preserva cofre) ou *reset destrutivo* (perde cofre). |
| P5 | Terceiros (Google, provedor de SMTP) só recebem metadados mínimos (email, token de entrega). Nenhum segredo. |
| P6 | Tudo funciona offline/local-first: TOTP é RFC 6238 puro, WebAuthn é local, Google OIDC é a única peça que exige internet — e é opcional (conta local funciona sem rede). |

## 3. Distinção: identidade de acesso vs chave do cofre

```
┌─ Acesso (autentica no servidor) ──────────────────────┐
│ identidade   = Google OIDC  OU  email + auth_key      │
│ 2º fator     = TOTP (obrigatório)                     │
│ dispositivo  = WebAuthn/passkey + biometria (se há)   │
└────────────────────────────────────────────────────────┘
┌─ Cofre (só existe no navegador) ──────────────────────┐
│ master_password ──Argon2id(salt_crypto)──▶ KEK        │
│ KEK unwrap▶ data_key ──AES-256-GCM──▶ segredos        │
│ recovery_key ──wrap▶ KEK  (envelope salvo no servidor)│
└────────────────────────────────────────────────────────┘
```

Google autentica *quem pode abrir o app*. A senha-mestra destranca *os dados*.
São planos independentes: comprometer o Google do usuário não revela nenhum
segredo; comprometer o servidor (zero-knowledge) também não.

## 4. Fluxos

### 4.1 Onboarding (conta local)

1. Email + senha-mestra (validação client-side: ≥12 chars, lista de senhas
   comuns, teclado-sequência — já existe em `frontend/src/crypto.ts`).
2. Cliente gera `salt_auth`/`salt_crypto`, deriva `auth_key` + KEK.
3. **Recovery key obrigatória**: cliente gera 32 bytes aleatórios, exibe como
   24 palavras (ou base64), exige confirmação de re-digitação, e envia ao
   servidor apenas `recovery_wrapped_kek` + `recovery_nonce`
   (KEK embrulhada pela recovery key via AES-256-GCM, no navegador).
4. **TOTP obrigatório**: backend gera secret, retorna URI otpauth:// para QR
   code; usuário confirma com um código de 6 dígitos válido.
5. Se WebAuthn disponível: registro de passkey (biometria do dispositivo).
6. Só após 3+4 o usuário é considerado ativo (`mfa_configured = true`).

### 4.2 Onboarding (Google OIDC)

1. "Entrar com Google" → fluxo OIDC padrão (authorization code + PKCE).
2. Backend cria/vincula a conta pelo `sub` + email verificado do Google.
3. **Ainda assim** o usuário define a senha-mestra do cofre na primeira
   sessão (ela não vem do Google; P2).
4. Passos 3–5 do fluxo local (recovery key + TOTP + passkey) — idênticos.

Regra dura: Google login **sem** TOTP confirmado não emite tokens definitivos;
a conta fica em estado `pending_mfa` e o vault não abre.

### 4.3 Login diário

```
identidade (Google ou email/auth_key)
    ▼ válida
mfa_challenge (JWT de vida curta, type="mfa_pending", 5 min)
    ▼ TOTP válido OU assertion WebAuthn válida
access_token + refresh_token
    ▼
navegador deriva KEK da senha-mestra + salt_crypto (desbloqueio do cofre)
```

- Em dispositivo com passkey registrada, a biometria substitui a digitação
  do TOTP no dia a dia — mas o TOTP continua existindo como fallback.
- Lockout progressivo já existente (`core/security.py`) aplica-se também às
  falhas de TOTP/WebAuthn, com contador independente.

### 4.4 Recuperação A — Com recovery key (preserva o cofre)

**Este é o único reset que não perde dados.**

1. Tela "Esqueci minha senha" → aba "Tenho minha recovery key".
2. Usuário informa email + recovery key (24 palavras ou base64).
3. Backend: identifica o usuário, retorna `recovery_wrapped_kek`,
   `recovery_nonce` e `salt_crypto` **somente após validação adicional**
   (ver 4.6). Nenhum segredo é verificável no servidor — o backend não sabe
   se a recovery key está certa; quem descobre é o cliente (AES-GCM falha
   na autenticação se a chave estiver errada).
4. Cliente: recovery key → AES-256-GCM unwrap → KEK antiga recuperada.
5. Cliente deriva nova `auth_key`, nova KEK (novos salts), re-wrapa todas as
   `data_key`s (mesmo payload de `change-password` — lógica já existente em
   `routers/auth.py`) e re-gera `recovery_wrapped_kek` com a nova KEK.
6. Backend (transação única): valida conjunto exato de entradas, atualiza
   `auth_hash`, `salt_auth`, `salt_crypto`, `wrapped_data_key` por entrada e
   `recovery_wrapped_kek`; revoga todas as sessões; emite novos tokens.
7. TOTP e passkeys **não são resetados** neste fluxo (a posse da recovery
   key + desafio por email já é a prova forte).

### 4.5 Recuperação B — Sem recovery key (destrutiva, último recurso)

Para quem perdeu senha-mestra **e** recovery key:

1. `POST /auth/password-reset/request` com o email. Resposta sempre
   `202 {"ok": true}` (não vaza existência de conta).
2. Backend gera token de reset (uso único, HMAC, `exp` 30 min), persiste só
   o hash, e envia link por email (SMTP local ou provedor gratuito de
   entrega).
3. Link abre `/reset?token=...`: `POST /auth/password-reset/validate`
   confirma validade.
4. UI deixa explícito: **"Seu cofre anterior será apagado
   permanentemente. Não há recuperação possível."** — confirmação em duas
   etapas (checkbox + digitação do email).
5. Cliente gera conta nova na prática: novos salts, nova `auth_key`, nova
   KEK, nova recovery key (onboarding reduzido: TOTP reconfigurado).
6. Backend: em transação, **apaga todas as `vault_entries`** do usuário,
   atualiza `auth_hash`/salts, marca token como usado, revoga sessões,
   reseta TOTP; emite novos tokens.

### 4.6 Canal de entrega do token

- **Local-first (padrão)**: deploy em 127.0.0.1 não precisa de email real.
  Modo `RESET_DELIVERY=local`: o token é exibido na resposta apenas quando a
  requisição vem de 127.0.0.1 E a conta tem TOTP — o usuário confirma um
  código TOTP atual para liberar o desafio. Prova máquina + 2FA.
- **LAN/público (opcional)**: `RESET_DELIVERY=smtp` com SMTP próprio ou
  Resend/Mailgun free tier. O email carrega só o link com token — nunca
  dados do cofre.

## 5. API proposta

Base: `/api/v1`. Novos endpoints:

| Método | Rota | Descrição |
|--------|------|-----------|
| POST | `/auth/oidc/google` | Troca `code`+`state` do Google por sessão (ou `mfa_pending`). |
| POST | `/auth/totp/setup` | Gera secret + URI otpauth:// (auth parcial exigida). |
| POST | `/auth/totp/confirm` | Confirma código, ativa `mfa_configured`. |
| POST | `/auth/mfa/verify` | 2ª etapa do login: `{mfa_token, totp_code}` ou assertion WebAuthn → tokens definitivos. |
| POST | `/auth/webauthn/register/*` | Cerimônia de registro de passkey. |
| POST | `/auth/webauthn/assert/*` | Cerimônia de assertion (login). |
| POST | `/auth/recovery/recover` | Reset com recovery key (payload = change-password + `recovery_key_proof`). |
| POST | `/auth/password-reset/request` | Inicia reset destrutivo. Sempre 202. |
| POST | `/auth/password-reset/validate` | Valida token (não autentica nada). |
| POST | `/auth/password-reset/confirm` | Executa reset destrutivo + novo auth_hash/salts. |

Contrato de `/auth/recovery/recover` (reusa o formato de `ChangePasswordIn`):

```json
{
  "email": "...",
  "totp_code": "123456",
  "new_auth_key": "b64",
  "new_salt_auth": "b64",
  "new_salt_crypto": "b64",
  "new_recovery_wrapped_data": {"wrapped_kek": "b64", "nonce": "b64"},
  "entries": [{"id": "...", "wrapped_data_key": "b64", "wrapped_nonce": "b64"}]
}
```

Validações server-side: conjunto de `entries` exatamente igual ao do usuário
(igual `change_password` hoje), TOTP válido, wrapped blobs nos tamanhos
corretos (48 bytes / 12 bytes — validadores já existem em `schemas.py`).

## 6. Modelo de dados

```sql
ALTER TABLE users
  ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'local',   -- 'local' | 'google'
  ADD COLUMN google_sub TEXT UNIQUE NULL,
  ADD COLUMN totp_secret_enc BYTEA NULL,                  -- secret TOTP (ver nota)
  ADD COLUMN mfa_configured BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN recovery_wrapped_kek TEXT NULL,              -- b64, KEK wrap pela recovery key
  ADD COLUMN recovery_nonce TEXT NULL;                    -- b64, 12 bytes

CREATE TABLE password_reset_tokens (
  id UUID PK,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,     -- hash do token, nunca o token
  expires_at TIMESTAMPTZ NOT NULL,
  used_at TIMESTAMPTZ NULL,
  request_ip_hash TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE webauthn_credentials (
  id UUID PK,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  credential_id BYTEA NOT NULL UNIQUE,  -- chave pública/credential id
  public_key BYTEA NOT NULL,
  sign_count BIGINT NOT NULL DEFAULT 0,
  transports TEXT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

Nota sobre `totp_secret_enc`: o TOTP secret **precisa** ser conhecido pelo
servidor (é um segredo compartilhado por definição do RFC 6238) — ele **não**
é dado do cofre, logo não quebra o zero-knowledge. Cifrar em repouso com
chave derivada de `JWT_SECRET` é o suficiente; não usar KEK do usuário
(isso criaria dependência circular no login).

## 7. Segurança ponta a ponta — por que continua zero-knowledge

| Ativo | Onde fica | Servidor vê? |
|-------|-----------|--------------|
| senha-mestra | memória do navegador | nunca |
| KEK | memória do navegador | nunca |
| data_key | memória + wrapped no banco | só blob |
| recovery key | com o usuário (papel/gerenciador) | nunca (só `recovery_wrapped_kek`) |
| segredos das entradas | ciphertext | nunca |
| auth_key | hashada (Argon2id) em `auth_hash` | só hash |
| TOTP secret | banco (segredo compartilhado, não é dado do cofre) | sim — por definição do protocolo |
| chaves WebAuthn | públicas | só públicas |

O modelo de ameaça fica: comprometer o **Google** não abre o cofre (falta
senha-mestra + TOTP passa pelo dispositivo); comprometer o **servidor** não
abre o cofre (zero-knowledge); comprometer o **email** só permite iniciar
reset destrutivo — que apaga o cofre, ou seja, não exfiltra nada legível;
comprometer a **recovery key** exige também email + TOTP no fluxo 4.6.

## 8. Riscos e mitigações

| Risco | Mitigação |
|-------|-----------|
| Usuário perde senha + recovery key | Esperado: reset destrutivo. Avisado em texto no onboarding. |
| Token de reset vazado | Uso único, 30 min, hash no banco, IP registrado, revogação automática. |
| Google account comprometida | TOTP obrigatório + senha-mestra independente (P2). |
| Phishing de página de reset | Reset destrutivo não revela nada; link HTTPS quando LAN/público. |
| Secret TOTP vazado do banco | Cifrado em repouso; ainda exige senha-mestra para KEK. |
| Abuso de `/password-reset/request` | Rate limit (slowapi já presente), sempre 202, cooldown por conta. |

## 9. Dependências

Backend: `pyotp` (TOTP), `authlib` (OIDC), `webauthn` (py-webauthn).
Frontend: QR code via `qrcode` (npm) — leve, sem servidor. Parse BIP39 para
as 24 palavras: lista EFF + checksum simples (evitar dependência pesada de
bip39 se possível; avaliar tamanho).

Tudo MIT/Apache, sem serviço pago obrigatório. Google OIDC exige registrar
um Client ID (gratuito) mas é opcional.

## 10. Plano de implementação

### Fase 1 — MFA local (base)
- Migração: campos `totp_secret_enc`, `mfa_configured`, `auth_method` em users.
- Endpoints TOTP (`setup`/`confirm`/`verify` com `mfa_pending`).
- UI: QR code no onboarding (local e Google), etapa de código no login.
- Bloqueio de cofre sem `mfa_configured`.
- Testes: fluxo completo local, código errado, lockout, token expirado.

### Fase 2 — Recovery key + reset
- Migração: `recovery_wrapped_kek`, `recovery_nonce`, `password_reset_tokens`.
- Onboarding: geração/exibição/confirmação da recovery key (obrigatória).
- `POST /auth/recovery/recover` (reusa lógica de `change_password`).
- `request/validate/confirm` do reset destrutivo com wipe transacional.
- Modo `RESET_DELIVERY=local|smtp`.
- Testes: recover com recovery key (cofre intacto), recover com key errada
  (falha de AES-GCM no cliente), reset destrutivo (entries zeradas), token
  usado/expirado, 202 sem vazar conta.

### Fase 3 — Google OIDC
- Migration: `auth_method`, `google_sub`.
- Endpoint OIDC (code + PKCE, verificação de id_token: iss/aud/exp/nonce).
- Conta Google → estado `pending_mfa` até TOTP configurado.
- UI: botão "Entrar com Google" na tela de login.
- Testes: primeiro login Google, vínculo com conta existente por email,
  rejeição de email não verificado.

### Fase 4 — WebAuthn / biometria
- Tabela `webauthn_credentials`, cerimônias registro/assertion.
- Biometria como etapa de conveniência no login diário (substitui TOTP
  naquele dispositivo; TOTP permanece como fallback).
- Feature-detect: se o navegador não suportar, fluxo cai em TOTP puro.
- Testes: registro, assertion válida, sign_count regressivo (clone detect).

## 11. Critérios de aceite

1. Usuário novo (local ou Google) **só acessa o cofre** após configurar
   recovery key + TOTP.
2. Login sem TOTP/WebAuthn válido não emite access token definitivo.
3. Reset com recovery key mantém todas as entradas legíveis com a nova
   senha-mestra.
4. Reset sem recovery key apaga o cofre (verificado no banco) e exige
   confirmação dupla na UI.
5. Em nenhum endpoint o servidor recebe senha-mestra, KEK ou recovery key
   (verificado por inspeção de payloads nos testes).
6. Tokens de reset: uso único, expiração ≤60 min, só hash persistido.
7. Modo local (127.0.0.1) funciona sem internet; Google OIDC é opcional.
8. `make test` verde (backend pytest + frontend vitest).

## 12. Fora de escopo

- HIBP (Have I Been Pwned) — já cortado no health dashboard, mesma razão.
- Extensão de navegador / autofill.
- Compartilhamento de cofres entre usuários (quando chegar, passkeys
  ajudam na UX mas não mudam este design).
- SaaS/multi-tenant — a arquitetura aqui é compatível, mas o hardening de
  produção pública (CSP, WAF, SMTP transacional) entra na fase Render.
