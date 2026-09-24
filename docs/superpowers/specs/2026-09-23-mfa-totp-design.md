# Spec: MFA local (TOTP) — Fase 1 da RFC de autenticação forte

- Status: Aprovado (design)
- Data: 2026-09-23
- Origem: `docs/superpowers/specs/2026-09-23-forgot-password-rfc.md`, Fase 1 do plano de implementação (seção 10)

## 1. Escopo

Este spec cobre **apenas a Fase 1** da RFC v2: TOTP obrigatório para contas
locais (email + senha-mestra). Fora de escopo aqui (fases futuras, specs
próprios): recovery key, reset destrutivo, Google OIDC, WebAuthn.

Objetivo: nenhum usuário abre o cofre sem TOTP configurado e verificado,
mantendo o modelo zero-knowledge (o TOTP secret é segredo compartilhado por
definição do RFC 6238 — não é dado do cofre, então o servidor pode vê-lo,
cifrado em repouso).

## 2. Modelo de dados

Migração Alembic nova em `backend/alembic/versions/`, adicionando a `users`:

```sql
ALTER TABLE users
  ADD COLUMN auth_method TEXT NOT NULL DEFAULT 'local',
  ADD COLUMN totp_secret_enc BYTEA NULL,
  ADD COLUMN mfa_configured BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN totp_failed_attempts INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN totp_locked_until TIMESTAMPTZ NULL;
```

- `auth_method`: só `'local'` é usado nesta fase; campo existe porque a
  Fase 3 (Google OIDC) da RFC precisa dele e é mais barato migrar uma vez.
- `totp_secret_enc`: secret TOTP (base32, ~20 bytes) cifrado com Fernet,
  chave derivada via HKDF-SHA256 do `JWT_SECRET` (info=`"totp"`, salt fixo
  de app). Nunca cifrado com KEK do usuário — dependência circular no login.
- `mfa_configured`: gate de acesso ao cofre. `False` por padrão cobre tanto
  contas novas (antes do setup) quanto contas existentes na migração
  (forçadas a configurar no próximo login — ver seção 4).
- `totp_failed_attempts` / `totp_locked_until`: contador de lockout
  **independente** do par `failed_login_attempts` / `locked_until` que já
  existe para a senha. Mesma função `lockout_duration_minutes()` de
  `core/security.py` (dobra a cada falha após o limiar, cap 60min).

`backend/app/models.py`: adicionar os 5 campos em `User`.

## 3. Cifra do TOTP secret em repouso

`backend/app/core/security.py` (ou novo `core/totp.py`):

```python
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import base64

def _totp_fernet_key() -> bytes:
    kdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"totp")
    raw = kdf.derive(settings.JWT_SECRET.encode())
    return base64.urlsafe_b64encode(raw)

def encrypt_totp_secret(secret: str) -> bytes:
    return Fernet(_totp_fernet_key()).encrypt(secret.encode())

def decrypt_totp_secret(token: bytes) -> str:
    return Fernet(_totp_fernet_key()).decrypt(token).decode()
```

Biblioteca `pyotp` gera o secret (`pyotp.random_base32()`) e valida códigos
(`pyotp.TOTP(secret).verify(code, valid_window=1)`).

## 4. Fluxo de login — state machine

Hoje `POST /auth/login` valida `auth_key` e devolve `TokenOut` direto. Isso
muda: a senha correta nunca mais emite `access_token`/`refresh_token`
sozinha — só libera um token parcial.

```
POST /auth/login {email, auth_key}
    │ senha inválida → 401 (lockout de senha já existente, sem mudança)
    │ senha válida
    ▼
mfa_configured == false?
    ├─ sim → {status: "mfa_setup_required", mfa_token}
    └─ não → {status: "mfa_verify_required", mfa_token}
```

`mfa_token`: JWT novo tipo `type="mfa_pending"`, `sub=user_id`, `exp` 5min,
mesma família de `create_access_token`/`create_refresh_token` (reusa
`jwt.encode` com `settings.JWT_SECRET`).

Endpoints novos (`backend/app/routers/auth.py`):

| Método | Rota | Auth | Comportamento |
|---|---|---|---|
| POST | `/auth/totp/setup` | `mfa_token` (`mfa_pending`) | Gera secret novo, grava `totp_secret_enc` (idempotente enquanto `mfa_configured=false`), devolve `{secret, otpauth_uri}`. 409 se `mfa_configured=true`. |
| POST | `/auth/totp/confirm` | `mfa_token` | Body `{totp_code}`. Valida contra secret recém-gerado; sucesso → `mfa_configured=true`, emite `access_token`+`refresh_token` (cria `Session`, igual ao login atual). Falha → 401, não ativa. |
| POST | `/auth/mfa/verify` | `mfa_token` | Body `{totp_code}`. Só quando `mfa_configured=true`. Sucesso → emite tokens (cria `Session`). Falha → incrementa `totp_failed_attempts`, aplica `totp_locked_until` progressivo, 401 (ou 429 se já bloqueado). |

`otpauth_uri`: formato padrão `pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="VaultLocal")`.

Dependency nova em `deps.py`: `get_mfa_pending_user(creds) -> User`, análoga a
`get_current_user` mas valida `type="mfa_pending"` em vez de `"access"`.

## 5. Bloqueio de acesso ao cofre

Nenhuma mudança em `get_current_user`/`/entries/*`: a garantia é estrutural
— `access_token` só é emitido por `/auth/totp/confirm` ou `/auth/mfa/verify`,
nunca por `/auth/login` sozinho. Um token de acesso emitido continua válido
pelos 15min normais (sem re-checar `mfa_configured` a cada request).

## 6. Migração de usuários existentes

Sem migração de dados além do `ALTER TABLE` (defaults cobrem linhas
existentes: `mfa_configured=false`). No próximo login, esses usuários caem
em `mfa_setup_required` automaticamente — senha continua válida, só ganham
uma tela obrigatória de configurar TOTP antes de reentrar no cofre. Ninguém
fica trancado permanentemente.

## 7. Frontend

- `frontend/src/api.ts`:
  - `login()` muda o tipo de retorno para o union
    `{status: 'mfa_setup_required' | 'mfa_verify_required', mfa_token: string}`
    (o caso `status: 'ok'` teoricamente nunca ocorre nesta fase, mas o tipo
    fica preparado).
  - novos: `totpSetup(mfa_token)`, `totpConfirm(mfa_token, totp_code)`,
    `mfaVerify(mfa_token, totp_code)` → todos devolvem `{access_token, refresh_token}`.
- `frontend/src/pages/Login.tsx`: após `api.login()`:
  - `mfa_setup_required` → renderiza tela de setup: chama `totpSetup`,
    mostra `otpauth_uri` como QR (lib `qrcode`, renderizado client-side, sem
    request extra) + texto copiável, campo de 6 dígitos → `totpConfirm`.
  - `mfa_verify_required` → tela simples de campo de 6 dígitos → `mfaVerify`.
  - Em ambos os casos, só após sucesso: `setTokens` + `deriveKek` (senha já
    está em memória do form) + `setSessionKek` + `onLogin()` + navigate.
- `frontend/src/pages/Register.tsx`: sem mudança de payload. Após registro,
  o próximo login cai automaticamente em `mfa_setup_required`.
- Nova dependência npm: `qrcode` (+ `@types/qrcode` dev).

## 8. Erros e edge cases

- Código TOTP errado em `/confirm` ou `/verify` → 401, `mfa_configured`
  permanece como estava.
- Lockout de TOTP atingido → 429 com `retry_after` (mesmo formato do lockout
  de senha existente).
- `mfa_token` expirado/inválido/tipo errado → 401 em qualquer um dos três
  endpoints; frontend trata como sessão expirada, volta pro login.
- `/auth/totp/setup` chamado com `mfa_configured=true` → 409 (reconfiguração
  de TOTP fica fora de escopo desta fase — pertence a um fluxo futuro de
  "gerenciar segurança da conta").
- Rate limiting: `/auth/mfa/verify` e `/auth/totp/confirm` ganham o mesmo
  `@limiter.limit` já usado em `/auth/login` (5/minute) — mitiga brute-force
  de 6 dígitos combinado com o lockout progressivo.

## 9. Testes (`backend/tests/test_auth.py`)

1. Registro + login novo → `mfa_setup_required`.
2. `/totp/setup` com `mfa_token` válido → devolve `otpauth_uri` válido, secret
   persistido cifrado (não em texto plano no banco).
3. `/totp/confirm` com código correto → `mfa_configured=true`, tokens
   emitidos, sessão criada.
4. `/totp/confirm` com código errado → 401, `mfa_configured` continua false.
5. Usuário com `mfa_configured=true` faz login → `mfa_verify_required`.
6. `/mfa/verify` código correto → tokens emitidos.
7. `/mfa/verify` código errado repetido → lockout progressivo (`totp_locked_until`),
   independente do lockout de senha.
8. `mfa_token` expirado → 401 em setup/confirm/verify.
9. Usuário existente (fixture sem `mfa_configured`, simulando pré-migração)
   loga com senha ok → cai em `mfa_setup_required`.
10. `/entries` sem `access_token` (só com `mfa_token`) → 401 (garante que
    token parcial não abre o cofre).

Frontend (`vitest`, se houver suíte equivalente): fluxo de setup renderiza
QR e avança após confirmar; fluxo de verify pede só o código.

## 10. Critérios de aceite

1. Usuário novo só acessa `/entries` depois de `/totp/confirm` bem-sucedido.
2. Usuário existente (mfa_configured=false por default) é forçado ao setup
   no próximo login, sem perda de acesso à conta.
3. Login com senha correta nunca emite `access_token` diretamente — sempre
   passa por `mfa_pending` → confirm/verify.
4. TOTP secret nunca é lido em texto plano do banco (sempre via
   `decrypt_totp_secret`, chave fora do banco).
5. Falhas de TOTP têm lockout progressivo próprio, sem interferir no
   contador de falhas de senha.
6. `make test` verde (backend pytest).

## 11. Fora de escopo (fases futuras da RFC)

- Recovery key, reset destrutivo de senha (Fase 2).
- Google OIDC (Fase 3).
- WebAuthn/passkey (Fase 4).
- Reconfiguração de TOTP após já ativo (troca de dispositivo, etc.).
