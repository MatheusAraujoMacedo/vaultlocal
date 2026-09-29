# VaultLocal

Gerenciador de senhas self-hosted, local-first, com criptografia zero-knowledge
end-to-end. Stack: FastAPI + React + Postgres via Docker Compose. Bind padrão
em `127.0.0.1`.

> O servidor nunca vê a senha-mestra, a KEK ou qualquer segredo em claro.

## Arquitetura em 30 segundos

```
┌─────────────────────────── Docker Compose ───────────────────────────┐
│                                                                      │
│  web  (nginx)        api  (FastAPI)         db  (Postgres 16)        │
│  127.0.0.1:8080 ───▶  proxy /api ────────▶  interno :8000 ───▶ :5432 │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘

browser (React)
  ├─ Argon2id(senha-mestra, salt_crypto) ──▶ KEK     (WASM, só memória)
  ├─ AES-256-GCM(KEK, data_key)           ──▶ wrapped_data_key
  └─ AES-256-GCM(data_key, segredo)       ──▶ ciphertext por campo
       ▲                                             │
       └──────────────── unwrap/decrypt ◀────────────┘
```

Zero-knowledge: o banco persiste apenas `username_enc`/`password_enc`/
`notes_enc`/`wrapped_data_key`/`wrapped_nonce` + `title`/`site`/`tags` em claro
(trade-off de busca, documentado em `SPEC.md §6`).

## Requisitos

- Docker com compose v2 (única dependência obrigatória)
- Para dev local sem Docker: Node 20+, Python 3.12+, `uv` (recomendado)

## Quick start

```bash
cp .env.example .env
# edite .env: defina DB_PASSWORD forte, JWT_SECRET com 64 hex chars e
# TOTP_ENCRYPTION_KEY com 64 hex chars.
# Recomendado: openssl rand -hex 32 para cada uma das duas chaves.
# Google OIDC é opcional: preencha GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET
# e mantenha GOOGLE_REDIRECT_URI exatamente como registrado no Google.
docker compose up -d --build
```

Acesse **http://localhost:8080**. No primeiro acesso você cria a conta,
configura o **autenticador TOTP** (QR code) e recebe a **recovery key** —
guarde-a offline.

## Features

- **Envelope encryption por entrada** — AES-256-GCM com `data_key` único por
  entrada, wrap em KEK derivada por Argon2id (`time_cost=3`, `memory=64MB`,
  `parallelism=2`). O formato v2 usa AAD para vincular cada blob ao `entry_id`
  e aos metadados da entrada. Rotação de senha-mestra = rewrap por entrada.
- **Zero-knowledge E2E** — derivação KEK e cifragem no navegador
  (`hash-wasm` + WebCrypto). Backend só vê blobs.
- **MFA obrigatório (TOTP)** — RFC 6238, secret cifrado em repouso (Fernet
  com uma `TOTP_ENCRYPTION_KEY` independente de `JWT_SECRET`). Lockout progressivo
  independente por fator.
- **Google OIDC opcional** — Authorization Code + PKCE, `state`/`nonce`, validação
  do ID token e vínculo por `sub`. O Google autentica a identidade; a senha-mestra
  continua sendo a raiz do cofre para novos dispositivos.
- **Acesso rápido com WebAuthn/Passkey** — credencial com verificação do usuário,
  challenge de uso único e contador anti-replay. O PRF deriva no navegador uma chave
  de dispositivo usada para cifrar o envelope da KEK; o servidor nunca recebe o PRF
  nem a KEK em claro. Login rápido = Google ou e-mail + passkey confiável.
- **Gestão de dispositivos confiáveis** — múltiplas passkeys por conta, renomeação
  e revogação individual. A revogação exige step-up com TOTP.
- **Gerador de senhas local** — geração feita no navegador via Web Crypto, sem o servidor ver a senha gerada.
- **Busca** — sobre `title`/`site` (claro) server-side.
- **Health Dashboard** (`/health`) — score 0–100 do cofre; detecta senhas
  fracas (comprimento/comum/só-letras/só-dígitos), reutilizadas, antigas e
  comprometidas. Análise 100% client-side; servidor persiste só contagens agregadas.
  A checagem HIBP é opt-in e usa k-anonymity: o navegador envia apenas um prefixo
  de hash para consulta e faz o match completo localmente. Ver
  `docs/features/health-dashboard.md`.
- **Auditor/security headers** — CSP, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy` restritivas. Ver `docs/deployment/csp.md`.

## Roadmap (RFC ativa)

Fases documentadas em `docs/superpowers/specs/2026-09-23-forgot-password-rfc.md`.

Pontos de retomada:
- `docs/superpowers/plans/2026-09-28-vaultlocal-phase4-handoff.md` — handoff das Phases 1–4.2.
- `docs/superpowers/plans/2026-09-28-phase5-breach-check.md` — implementação e próximos passos da Phase 5.

| Fase | Entrega | Status |
|---|---|---|
| 1 | MFA local (TOTP) | ✅ implementado |
| 2 | Recovery key + reset destrutivo com token | ✅ implementado |
| 3 | Google OIDC como identidade (opcional) | ✅ implementado — E2E validado |
| 4 | WebAuthn / passkey para acesso rápido | ✅ 4.1 E2E browser validado; 4.2 implementado |
| 5 | Breach check | ✅ 5.1 HIBP online k-anonymity + ✅ 5.2 adapter para índice local; 📋 importar/atualizar corpus |

## Dev local (sem Docker)

Backend:
```bash
uv venv .venv
uv pip install --python .venv/bin/python -r backend/requirements.txt
cd backend && ../.venv/bin/uvicorn app.main:app --reload
```

Frontend (outro terminal):
```bash
cd frontend
npm install
npm run dev
```

Acesse http://127.0.0.1:5173 (proxy `/api → :8000` já configurado).

## Testes

```bash
make test           # backend (pytest)
make test-frontend  # frontend (vitest)
```

Estado atual: **106/106 backend**, **29/29 frontend**.

## Backup

```bash
make backup
```

Dump compactado em `backups/`. Os segredos do cofre permanecem como ciphertext,
mas o arquivo ainda contém metadados e hashes de autenticação. Uma exportação
portátil cifrada ponta a ponta será responsabilidade do cliente no roadmap.

## Estrutura do repositório

```
vaultlocal/
├── docker-compose.yml      # orquestração
├── Makefile                # up, down, backup, test, migrate
├── backend/
│   ├── app/
│   │   ├── main.py         # FastAPI app, CORS, registro de routers
│   │   ├── models.py       # User, VaultEntry, Session, HealthReport
│   │   ├── schemas.py      # Pydantic (contratos públicos)
│   │   ├── routers/        # auth, entries, health
│   │   ├── core/           # security (JWT/Argon2), limiter, totp
│   │   ├── webauthn_support.py # opções WebAuthn + helpers de RP
│   │   └── deps.py         # get_db, get_current_user, get_mfa_pending_user
│   ├── alembic/            # migrações (003 = TOTP, 002 = health_reports)
│   └── tests/              # pytest
├── frontend/
│   ├── src/
│   │   ├── pages/          # Login, Register, Vault, EntryForm, EntryDetail, Health
│   │   ├── crypto.ts       # Argon2id + AES-GCM via WebCrypto (KEK em memória)
│   │   ├── health/         # engine, rules, score (+ vitest)
│   │   └── api.ts          # fetch wrapper com Bearer
│   └── nginx.conf          # SPA + proxy /api + CSP/headers
├── SPEC.md                 # arquitetura formal
└── docs/
    ├── features/           # RFCs por feature (health-dashboard, ...)
    ├── superpowers/        # specs e plans de alto nível
    └── deployment/         # CSP, hardening, deploy
```

## Segurança — políticas mandatórias

1. **Zero-knowledge**: servidor nunca recebe senha-mestra, KEK, data_key ou
   plaintext. Verificável inspecionando payloads (testes cobrem isso).
2. **Bind 127.0.0.1** por padrão. Mudar exige editar `docker-compose.yml`
   conscientemente.
3. **MFA obrigatório** para qualquer conta ativa desde a Fase 1.
4. **Sem recuperação de senha-mestra**. Recovery key (Fase 2) é o único
   mecanismo de desbloqueio alternativo.
5. **Lockout progressivo** em `auth/login` e `auth/mfa/verify`
   (contadores independentes).
6. **Sessões revogáveis**: access tokens carregam `sid` e são aceitos somente
   enquanto a sessão correspondente existir e não estiver expirada; logout
   e troca de senha revogam as sessões antigas.
7. **Clipboard expiry**: frontend limpa a área de transferência 30s após
   copiar.
8. **`.env` gitignored** desde o commit 1.

Para a discussão completa de ameaças, mitigações e trade-offs: `SPEC.md §9`,
`docs/deployment/csp.md`, `docs/superpowers/specs/2026-09-23-forgot-password-rfc.md`.

## Licença

MIT (ver `LICENSE` se presente).
