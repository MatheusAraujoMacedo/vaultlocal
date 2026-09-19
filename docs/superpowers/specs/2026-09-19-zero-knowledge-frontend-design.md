# Zero-knowledge crypto no frontend (M6 do SPEC.md)

Data: 2026-09-19

## 1. Contexto

O SPEC (seções 5, 10, marco M6) já documenta este modelo; nunca foi
implementado. Hoje o backend deriva a KEK a partir de `master_password`
recebido em claro (login/register/change-password), guarda a KEK em memória
(`app/core/kekstore.py`) e criptografa/descriptografa os campos de cada
`VaultEntry` ele mesmo (`app/core/security.py: encrypt/decrypt`, usado em
`app/routers/entries.py`).

Objetivo: o servidor nunca vê `master_password`, nunca vê a KEK, nunca vê
texto plano de `username`/`password`/`notes`. `title`/`site` continuam em
claro no servidor (trade-off já registrado no SPEC linha 132, para permitir
busca server-side).

## 2. Modelo de chaves

```
master_password (só existe no navegador, nunca é enviado)
       │
       ├─▶ auth_key    = Argon2id(master_password, salt_auth)   ──▶ enviado ao servidor
       │                 (time_cost=3, memory=64MB, parallelism=2, hash_len=32)
       │
       └─▶ KEK          = Argon2id(master_password, salt_crypto) ── nunca sai do navegador
                            (mesmos parâmetros)

Por entrada:
  data_key            = 32 bytes aleatórios, gerados no navegador
  {ciphertext, nonce} = AES-256-GCM(data_key, campo_plaintext)      -- por campo
  wrapped_data_key    = AES-256-GCM(KEK, data_key)                  -- 1x por entrada
```

Rotação de senha-mestra (`/auth/change-password`) deriva uma nova KEK e
re-embrulha só a `data_key` de cada entrada (32 bytes) — não toca no
ciphertext dos segredos. Isso substitui o loop atual em
`app/routers/auth.py:change_password`, que hoje decripta e re-criptografa
cada campo inteiro; com envelope por entrada, o loop passa a rewrap de
`wrapped_data_key`, bem mais barato e é o que o SPEC 5.2 já descrevia.

**KDF no navegador:** Argon2id via `hash-wasm` (pacote npm, ~60KB, roda em
WASM), com os mesmos parâmetros do backend (`argon2-cffi`), para não
regredir a segurança documentada no SPEC. AES-GCM usa `window.crypto.subtle`
nativo (sem dependência extra).

**Onde a KEK/data_keys ficam em memória:** um módulo singleton
`frontend/src/crypto.ts` guarda a KEK (e as `data_key`s já desembrulhadas,
por entrada, sob demanda) em variáveis de módulo — nunca em
`localStorage`/`sessionStorage`. Limpo em logout e ao recarregar a página
(F5 = precisa logar de novo; isso já é aceitável e é o mesmo padrão hoje).
Indicador de "sessão de cripto expirou" / auto-lock por inatividade fica
para os itens de frontend já listados no roadmap (fora de escopo aqui).

## 3. Mudanças de API

### `POST /auth/login/init` (novo)
Request: `{"email": "..."}`
Response 200: `{"salt_auth": "<base64>", "salt_crypto": "<base64>"}`

Se o email não existe, responde com salts determinísticos e falsos
(`HMAC-SHA256(JWT_SECRET, "auth:"+email)` / `HMAC-SHA256(JWT_SECRET,
"crypto:"+email)`, truncados a 16 bytes) — mesma forma e tempo de resposta
de um email real, para não vazar quem tem conta. Sem rate limit adicional
aqui (não autentica nada, só entrega salts; login em si continua limitado).

### `POST /auth/register` (contrato muda)
Request: `{"email": str, "salt_auth": b64, "salt_crypto": b64, "auth_key": b64}`.
Um usuário novo não tem entradas ainda, então não há `wrapped_data_key` no
registro — isso só existe por entrada, criado em `POST /entries`.
`auth_key` é tratado exatamente como `master_password` era antes: passa por
`hash_password()` (Argon2id) e guarda em `auth_hash`. Backend não checa mais
senha comum (não vê a senha) — checagem de senha comum e comprimento mínimo
passam a ser 100% client-side em `crypto.ts` antes de derivar qualquer
chave. Isso é uma perda de garantia server-side aceita (mesmo trade-off do
Bitwarden/1Password: cliente malicioso sempre pode contornar validação
client-side, então a garantia real já não existia).

### `POST /auth/login` (contrato muda)
Request: `{"email": str, "auth_key": b64}` (era `master_password`).
Resposta inalterada (`TokenOut`), mas passa a incluir `wrapped_master_key`?
— não, a KEK não é embrulhada por nada no servidor (é derivada localmente a
cada login a partir da senha-mestra + `salt_crypto`, que o cliente já pediu
em `/auth/login/init`). Resposta continua `{access_token, refresh_token,
token_type}`, sem novidade de payload.
Lockout/rate-limit inalterados (continuam batendo em `auth_hash` vs
`auth_key`, mesma lógica, só troca o que é hasheado).

### `POST /auth/change-password` (contrato muda)
Request: `{"old_auth_key": b64, "new_auth_key": b64, "new_salt_auth": b64, "new_salt_crypto": b64, "entries": [{"id": str, "wrapped_data_key": b64, "wrapped_nonce": b64}, ...]}`
Servidor: verifica `old_auth_key` contra `auth_hash`; valida que o
conjunto de `id`s em `entries` é exatamente igual ao conjunto de
`VaultEntry.id` daquele usuário (nem faltando, nem de outro usuário) —
senão 400 sem aplicar nada, para não deixar nenhuma entrada presa sob a
KEK antiga. Se bate, em uma transação: atualiza `auth_hash`, `salt_auth`,
`salt_crypto`; atualiza `wrapped_data_key`/`wrapped_nonce` de cada
`VaultEntry` listado; revoga sessões antigas; cria sessão nova; retorna
`TokenOut`. Servidor nunca decripta nada — só troca blobs opacos.

### `/entries` (contrato muda)
`EntryIn`/`EntryOut` deixam de ter `username`/`password`/`notes` em claro:

```
EntryIn:
  title: str
  site: str | None
  username_enc: str (b64), nonce_username: str (b64)
  password_enc: str (b64), nonce_password: str (b64)
  notes_enc: str | None, nonce_notes: str | None
  wrapped_data_key: str (b64), wrapped_nonce: str (b64)
  tags: str

EntryOut: mesmos campos (sem decriptar nada) + id, created_at, updated_at
```

`app/routers/entries.py` para de chamar `encrypt()`/`decrypt()` — só
persiste/retorna os blobs. `get_current_user_with_kek` e `kekstore.py`
somem (nada mais precisa de KEK no servidor); `entries.py` passa a usar só
`get_current_user`.

`GET /entries` e `/entries/search` continuam devolvendo `title`/`site` em
claro (inalterado, é o trade-off de busca já aceito).

## 4. Mudança de schema (`vault_entries`)

```sql
ALTER TABLE vault_entries
  ADD COLUMN wrapped_data_key TEXT NOT NULL,
  ADD COLUMN wrapped_nonce   TEXT NOT NULL;
```

Sem dado real em produção ainda (só contas de smoke test) — decisão
confirmada: **zera `users`, `vault_entries`, `sessions`** antes de aplicar a
migração, em vez de escrever fallback de compatibilidade pro esquema
antigo. A migração alembic faz `TRUNCATE` dessas 3 tabelas antes de
`ADD COLUMN ... NOT NULL` (sem `server_default`, já que não há linha
remanescente para popular).

## 5. Mudanças de backend (arquivos)

- `app/models.py`: `VaultEntry` ganha `wrapped_data_key`, `wrapped_nonce`.
- `app/schemas.py`: `RegisterIn`, `LoginIn`, `ChangePasswordIn` trocam
  `master_password`/`old_master_password`/`new_master_password` por
  `auth_key`/`old_auth_key`/`new_auth_key` (+ salts onde aplicável);
  `EntryIn`/`EntryOut` trocam campos em claro por blobs + wrapped key; novo
  `LoginInitIn`/`LoginInitOut`.
- `app/routers/auth.py`: novo `/login/init`; `register`/`login` passam a
  operar sobre `auth_key`; `change_password` vira rewrap-only (sem
  decrypt/encrypt de entradas, sem depender de `VaultEntry` plaintext);
  remove `is_common_password` (checagem sai do backend).
- `app/routers/entries.py`: remove `encrypt`/`decrypt`/`_to_out`; CRUD passa
  blobs direto; troca `get_current_user_with_kek` por `get_current_user`.
- `app/core/kekstore.py`: **deletado**.
- `app/core/common_passwords.py`: **deletado do backend**, conteúdo migra
  (traduzido) para `frontend/src/crypto.ts`.
- `app/core/security.py`: perde `encrypt`/`decrypt` (nada mais usa
  server-side) e `derive_kek` (idem); mantém `hash_password`/
  `verify_password` (agora operando sobre `auth_key`, não mais sobre a
  senha), `create_access_token`/`create_refresh_token`/`verify_token`,
  `lockout_duration_minutes`.
- `app/deps.py`: remove `get_current_user_with_kek` e o import de
  `kekstore`.
- Nova migration alembic (`0003_zero_knowledge.py`).

## 6. Mudanças de frontend (arquivos)

- **Novo** `frontend/src/crypto.ts`: Argon2id (hash-wasm), AES-GCM
  (WebCrypto nativo), geração de salt/data_key, wrap/unwrap, checagem de
  senha comum (porta do que hoje está em
  `backend/app/core/common_passwords.py`), estado em memória (KEK atual).
- `frontend/src/api.ts`: `register`/`login` passam a chamar
  `crypto.ts` antes de montar o payload; `createEntry`/`updateEntry`/
  `getEntry`/`listEntries` cifram/decifram usando a KEK em memória; novo
  `loginInit`.
- `frontend/src/pages/Login.tsx`: fluxo de 2 passos (`loginInit` → deriva
  `auth_key`+KEK → `login`); guarda KEK no módulo `crypto.ts`, não em
  estado de componente.
- `frontend/src/pages/Register.tsx`: gera salts no cliente, deriva
  `auth_key`, checagem de senha comum client-side (mensagem de erro igual
  à atual).
- `frontend/src/pages/EntryForm.tsx`: cifra campos antes de enviar ao criar/
  editar; ao editar, busca a entrada (blobs) e decifra antes de popular o
  formulário.
- `frontend/src/pages/EntryDetail.tsx`: decifra ao exibir.
- `frontend/src/pages/Vault.tsx`: inalterado (só usa `title`/`site`, que
  seguem em claro).
- `package.json`: adiciona `hash-wasm`.

## 7. Testes

`backend/tests/test_auth.py` e `test_entries.py` — a maior parte precisa
reescrever os payloads (auth_key em vez de master_password, blobs em vez de
username/password em claro nas entradas) e adaptar os asserts de
change-password (não mexe mais em ciphertext de segredo, só em
wrapped_data_key). `test_common_passwords.py` é removido do backend (a
lógica não existe mais lá). Sem teste automatizado de frontend nesta
passada (fora do que já existe no projeto — não há suíte de frontend hoje).

## 8. Fora de escopo (fica para os itens já listados no roadmap)

- Auto-lock por inatividade / indicador de "sessão de cripto expirou" —
  já são itens separados do roadmap do usuário, não bloqueiam esta mudança.
- Extensão de navegador, compartilhamento entre usuários, deploy Render —
  não afetados por este design.
