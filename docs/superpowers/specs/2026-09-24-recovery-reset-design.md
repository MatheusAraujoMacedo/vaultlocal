# Spec: Recovery key + reset destrutivo — Fase 2 da RFC de autenticação forte

- Status: Aprovado (design)
- Data: 2026-09-24
- Origem: `docs/superpowers/specs/2026-09-23-forgot-password-rfc.md`, Fase 2 do plano de implementação (seção 10, seções 4.1.3/4.4/4.5/4.6/5/6)

## 1. Escopo

Cobre apenas a Fase 2 da RFC v2: recovery key obrigatória no onboarding,
recuperação com recovery key (preserva o cofre) e reset destrutivo por email
(último recurso). Fora de escopo: Google OIDC (Fase 3), WebAuthn (Fase 4).

## 2. Decisões que fecham lacunas da RFC

A RFC descreve os fluxos em prosa; estas decisões tornam o design
implementável sem contradizer nenhum princípio (P1-P6) ou critério de
aceite da RFC.

**D1 — Formato da recovery key.** 32 bytes aleatórios, exibidos como base64
em blocos de 4 caracteres (não BIP39/24-palavras): a RFC permite explicitamente
"24 palavras (ou base64)" e adiar a lista BIP39 evita dependência nova de
peso incerto (RFC §9, "avaliar tamanho"). Confirmação por re-digitação exata
antes de prosseguir (RFC §4.1.3).

**D2 — Fluxo de recuperação em 3 chamadas, não 1.** A RFC esboça
`/auth/recovery/recover` com um payload único (email + totp_code + novo
material + `entries`), mas o cliente só pode montar `entries` (rewrap de
cada `data_key`) se antes souber o `wrapped_data_key`/`wrapped_nonce` atual
de cada entrada — e essa lista é sensível, não pode ser exposta sem
verificar o segundo fator primeiro. Por isso:

1. `POST /auth/recovery/init` — público, sem segundo fator, devolve
   `salt_crypto` + `recovery_wrapped_kek` + `recovery_nonce` (ou blobs falsos
   determinísticos se a conta não existir/não tiver recovery key — mesmo
   padrão anti-enumeração de `/auth/login/init`). O cliente decide localmente
   se a recovery key está certa (a descriptografia AES-GCM falha se estiver
   errada); o servidor nunca sabe o resultado dessa checagem (RFC §4.4.3).
2. `POST /auth/recovery/verify` — público, rate-limited, exige `email` +
   `totp_code` correto (prova de posse do 2º fator, já que a senha é
   desconhecida). Sucesso: devolve `recovery_token` (JWT `type="recovery_pending"`,
   5 min, mesma família de `mfa_pending`) + a lista atual de
   `entries: [{id, wrapped_data_key, wrapped_nonce}]`.
3. `POST /auth/recovery/recover` — autenticado via `recovery_token`. Body =
   novo `auth_key`/salts/`recovery_wrapped_kek`/`recovery_nonce` + `entries`
   re-wrapped. Mesma checagem de conjunto exato de `entries` que
   `change-password` já faz hoje.

TOTP e `mfa_configured` **não são resetados** neste fluxo (RFC §4.4.7) —
só o 3º passo muda estado, e só dos campos de auth/crypto/recovery.

**D3 — Gate de configuração da recovery key.** Reaproveita o `mfa_token`
existente (`type="mfa_pending"`) em vez de criar outro tipo de token: o
onboarding de conta nova e o "alcance" de conta que já passou pela Fase 1
mas ainda não tem recovery key (`mfa_configured=true`,
`recovery_wrapped_kek=None`) passam pelo mesmo estado — o login já emite um
`mfa_token` novo em ambos os casos. `POST /auth/recovery/setup` grava
`recovery_wrapped_kek`/`recovery_nonce` e devolve `409` se já estiver
configurada (mesma semântica de `/auth/totp/setup`).

**D4 — `LoginOut.status` ganha um terceiro valor.**
```
senha válida
    ├─ mfa_configured == false          → "mfa_setup_required"
    ├─ mfa_configured == true
    │     └─ recovery_wrapped_kek None  → "recovery_setup_required"
    └─ mfa_configured == true e recovery_wrapped_kek setada → "mfa_verify_required"
```
Onboarding de conta nova cai em `mfa_setup_required`; a UI mostra recovery-key
setup e TOTP setup em sequência (RFC §4.1 ordena recovery antes de TOTP),
reusando o mesmo `mfa_token` para as duas chamadas. Conta que já tinha TOTP
da Fase 1 mas nunca configurou recovery key cai em `recovery_setup_required`
uma única vez; depois disso, `mfa_verify_required` normal.

**D5 — Token de reset destrutivo.** `secrets.token_urlsafe(32)`, nunca
persistido em claro — grava-se `HMAC-SHA256(JWT_SECRET, token)` em hex
(determinístico, permite `WHERE token_hash = ...`; Argon2id não serve aqui
porque cada hash tem salt próprio e não é buscável por igualdade). Expira em
30 min, uso único (`used_at`), tabela `password_reset_tokens` (RFC §6).

**D6 — Modo de entrega (`RESET_DELIVERY`).** `local` (padrão): o endpoint de
request só revela o token na própria resposta quando a origem é
`127.0.0.1` **e** o corpo inclui um `totp_code` válido da conta (RFC §4.6 —
prova máquina + 2FA). `smtp` (opcional, RFC §4.6): envia um link por
`smtplib` (stdlib, sem dependência nova) via `asyncio.to_thread`; nunca
revela o token na resposta HTTP. Ambos os modos sempre devolvem `202
{"ok": true}` — nunca vazam se a conta existe.

**D7 — Reset destrutivo apaga também MFA/recovery.** RFC §4.5.5 diz
"onboarding reduzido: TOTP reconfigurado"; por coerência, o reset destrutivo
zera `mfa_configured`, `totp_secret_enc`, `recovery_wrapped_kek`,
`recovery_nonce` além de apagar `vault_entries` — a conta renasce e passa
pelo onboarding completo (recovery key + TOTP) no próximo login, como uma
conta nova.

## 3. Modelo de dados

Migração Alembic nova (`004_add_recovery_and_reset.py`), `down_revision =
"003_add_totp_mfa_fields"`:

```sql
ALTER TABLE users
  ADD COLUMN recovery_wrapped_kek TEXT NULL,
  ADD COLUMN recovery_nonce TEXT NULL;

CREATE TABLE password_reset_tokens (
  id                UUID PK,
  user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash        TEXT NOT NULL UNIQUE,
  expires_at        TIMESTAMPTZ NOT NULL,
  used_at           TIMESTAMPTZ NULL,
  request_ip_hash   TEXT NULL,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

`recovery_wrapped_kek`/`recovery_nonce`: base64, tamanho decodificado 48/12
bytes (mesma convenção de `wrapped_data_key`/`wrapped_nonce` — AES-256-GCM,
16 bytes de tag).

## 4. Criptografia cliente (`frontend/src/crypto.ts`)

Novas funções, aditivas — não alteram `deriveKek`/`getSessionKek` (a KEK de
sessão continua não-extraível; a exportação de bytes crus só acontece durante
onboarding/recuperação, quando a senha-mestra já está em memória do form):

```ts
export async function deriveRawKek(password: string, saltCryptoB64: string): Promise<Uint8Array>
export function generateRecoveryKey(): Uint8Array                       // 32 bytes aleatórios
export function recoveryKeyToDisplay(bytes: Uint8Array): string         // base64 em blocos de 4 chars
export function recoveryKeyFromDisplay(display: string): Uint8Array     // remove espaços, b64decode
export interface RecoveryWrap { recovery_wrapped_kek: string; recovery_nonce: string }
export async function wrapKekWithRecoveryKey(rawKek: Uint8Array, recoveryKey: Uint8Array): Promise<RecoveryWrap>
export async function unwrapKekWithRecoveryKey(wrapped: RecoveryWrap, recoveryKey: Uint8Array): Promise<Uint8Array>
```

Se a recovery key estiver errada, `unwrapKekWithRecoveryKey` rejeita
(`OperationError` do WebCrypto, falha de tag AES-GCM) — o cliente mostra erro
genérico, nunca chega a montar um payload de recuperação.

## 5. API

Base `/api/v1`. Novos endpoints (todos em `backend/app/routers/auth.py`):

| Método | Rota | Auth | Rate limit |
|---|---|---|---|
| POST | `/auth/recovery/setup` | `mfa_token` | — |
| POST | `/auth/recovery/init` | público | 5/minute |
| POST | `/auth/recovery/verify` | público (email+totp_code) | 5/minute |
| POST | `/auth/recovery/recover` | `recovery_token` | — |
| POST | `/auth/password-reset/request` | público | 3/minute |
| POST | `/auth/password-reset/validate` | público (token) | — |
| POST | `/auth/password-reset/confirm` | público (token) | 5/minute |

Contratos (`backend/app/schemas.py`):

```python
class RecoverySetupIn(BaseModel):
    recovery_wrapped_kek: str   # b64, 48 bytes
    recovery_nonce: str         # b64, 12 bytes

class RecoveryInitIn(BaseModel):
    email: EmailStr

class RecoveryInitOut(BaseModel):
    salt_crypto: str
    recovery_wrapped_kek: str
    recovery_nonce: str

class RecoveryVerifyIn(BaseModel):
    email: EmailStr
    totp_code: str   # 6 digits

class RecoveryEntry(BaseModel):
    id: str
    wrapped_data_key: str
    wrapped_nonce: str

class RecoveryVerifyOut(BaseModel):
    recovery_token: str
    entries: list[RecoveryEntry]

class RecoverIn(BaseModel):
    new_auth_key: str
    new_salt_auth: str
    new_salt_crypto: str
    new_recovery_wrapped_kek: str
    new_recovery_nonce: str
    entries: list[ChangePasswordEntryRewrap]   # reuso do tipo existente

class PasswordResetRequestIn(BaseModel):
    email: EmailStr
    totp_code: str | None = None   # só usado em RESET_DELIVERY=local

class PasswordResetRequestOut(BaseModel):
    ok: bool = True
    token: str | None = None       # só presente em RESET_DELIVERY=local + loopback + totp ok

class PasswordResetValidateIn(BaseModel):
    token: str

class PasswordResetConfirmIn(BaseModel):
    token: str
    new_auth_key: str
    new_salt_auth: str
    new_salt_crypto: str
```

## 6. Fluxo de recuperação com recovery key (detalhado)

1. Tela "Esqueci a senha-mestra" → aba "Tenho minha recovery key" → usuário
   digita email.
2. `POST /auth/recovery/init` → cliente guarda `salt_crypto` +
   `recovery_wrapped_kek`/`recovery_nonce`.
3. Usuário digita a recovery key → `unwrapKekWithRecoveryKey` → KEK antiga
   (bytes crus). Falha aqui = erro genérico, fim.
4. Usuário digita nova senha-mestra (validação client-side já existente:
   ≥12 chars, não comum) + código TOTP atual.
5. `POST /auth/recovery/verify {email, totp_code}` → `recovery_token` +
   `entries` atuais.
6. Cliente: para cada entrada, `unwrapDataKey(entry, kekAntiga)` →
   `wrapDataKey(dataKey, kekNova)` (funções já existentes em `crypto.ts`).
   Gera novos salts, nova `auth_key`, nova recovery key, novo
   `recovery_wrapped_kek` (wrap da KEK nova).
7. `POST /auth/recovery/recover` (header `Authorization: Bearer
   <recovery_token>`) com o payload montado. Sucesso → `TokenOut` (mesmo
   formato de `/auth/totp/confirm`), sessões antigas revogadas.

## 7. Fluxo de reset destrutivo (detalhado)

1. Tela "Esqueci a senha-mestra" → aba "Não tenho a recovery key".
2. Aviso obrigatório: "Seu cofre atual será apagado permanentemente." —
   checkbox + campo de re-digitação do email antes de habilitar o botão.
3. `RESET_DELIVERY=local`: formulário pede também o código TOTP atual (a
   máquina que acessa 127.0.0.1 e conhece o TOTP prova posse). `POST
   /auth/password-reset/request {email, totp_code}` — resposta inclui
   `token` só se IP for loopback e TOTP validar; senão `{ok: true}` sem
   token (mesmo endpoint, sem vazar qual dos dois faltou).
   `RESET_DELIVERY=smtp`: `POST /auth/password-reset/request {email}` —
   sempre `{ok: true}`; token é enviado por email.
4. `POST /auth/password-reset/validate {token}` confirma validade antes de
   mostrar o formulário final (evita gerar salts à toa com token já
   inválido).
5. Cliente gera conta "nova": novos salts, nova `auth_key`, nova KEK (sem
   recovery key ainda — onboarding completo acontece no próximo login).
6. `POST /auth/password-reset/confirm {token, new_auth_key, new_salt_auth,
   new_salt_crypto}` — transação: apaga `vault_entries`, atualiza
   `auth_hash`/salts, zera `mfa_configured`/`totp_secret_enc`/
   `recovery_wrapped_kek`/`recovery_nonce`, marca token usado, revoga
   sessões. Não emite tokens (usuário precisa logar de novo e passar pelo
   onboarding completo, igual conta nova).

## 8. Erros e edge cases

- `/auth/recovery/init` e `/auth/password-reset/request` sempre respondem
  com sucesso/formato genérico para email inexistente (anti-enumeração).
- `/auth/recovery/verify` com TOTP errado → incrementa
  `totp_failed_attempts`/`totp_locked_until` (mesmo contador do login/verify
  normal — é o mesmo segredo TOTP sendo atacado).
- `/auth/recovery/recover` com `entries` que não batem exatamente com as
  atuais → `400` (mesma regra de `change-password`).
- `recovery_token` expirado/inválido/tipo errado → `401` em
  `/auth/recovery/recover`.
- `/auth/recovery/setup` chamado com `recovery_wrapped_kek` já setada →
  `409`.
- Token de reset usado ou expirado → `400` em `validate`/`confirm`.
- `/auth/password-reset/request` em modo `local` sem `totp_code` ou de IP
  não-loopback → `{"ok": true}` sem `token` (silencioso, não é erro).

## 9. Testes (`backend/tests/test_recovery.py`, `test_password_reset.py`)

1. Onboarding: login de conta nova → `mfa_setup_required` →
   `/recovery/setup` grava blobs → `/totp/setup` + `/totp/confirm` → tokens.
2. Conta pós-Fase-1 sem recovery key loga → `recovery_setup_required` →
   `/recovery/setup` → `mfa_verify_required` no próximo login.
3. `/recovery/setup` chamado duas vezes → segunda vez `409`.
4. `/recovery/init` para email inexistente → blobs determinísticos, mesmo
   formato de conta real (mesmo tamanho b64).
5. `/recovery/verify` com TOTP correto → `recovery_token` + `entries`
   batendo com o banco.
6. `/recovery/verify` com TOTP errado repetido → lockout progressivo.
7. `/recovery/recover` com `entries` incompletas/a mais → `400`.
8. `/recovery/recover` completo → `auth_hash`/salts/recovery atualizados,
   `wrapped_data_key` de cada entrada atualizado, sessões antigas revogadas,
   `mfa_configured`/`totp_secret_enc` inalterados.
9. `/password-reset/request` sempre `202`/`{"ok": true}`; token só aparece
   em modo `local` + loopback + TOTP correto.
10. `/password-reset/confirm` válido → todas `vault_entries` do usuário
    apagadas, `mfa_configured=False`, `totp_secret_enc=None`,
    `recovery_wrapped_kek=None`, sessões revogadas.
11. `/password-reset/confirm` com token usado ou expirado → `400`.

Frontend (`vitest`): `crypto.ts` — round-trip `wrapKekWithRecoveryKey`/
`unwrapKekWithRecoveryKey`; unwrap com chave errada rejeita.

## 10. Critérios de aceite

1. Toda conta ativa tem recovery key configurada antes de acessar o cofre
   (novas contas) ou é forçada a configurar uma vez (contas pós-Fase-1).
2. Recuperar com recovery key correta preserva todas as entradas legíveis
   com a nova senha-mestra; nenhuma etapa expõe a KEK ao servidor.
3. Recuperar com recovery key errada nunca chega a enviar payload ao
   servidor (falha só no cliente).
4. Reset destrutivo sempre apaga as entradas e reresseta MFA/recovery;
   nunca é reversível.
5. `/auth/password-reset/request` nunca revela se o email existe.
6. Tokens de reset: uso único, `≤30min`, só hash persistido.
7. `make test` verde (backend pytest + frontend vitest).

## 11. Fora de escopo (fases futuras da RFC)

- Google OIDC (Fase 3), WebAuthn/passkey (Fase 4).
- Lista BIP39 de 24 palavras para a recovery key (fica em base64 por ora).
- Envio de email real em produção (modo `smtp` cobre o mecanismo; provedor
  de entrega concreto — Resend/Mailgun — é configuração de deploy, não
  código novo).
