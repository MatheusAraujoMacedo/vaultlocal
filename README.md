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
docker compose up -d --build
```

Acesse **http://127.0.0.1:8080**. No primeiro acesso você cria a conta,
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
  com chave derivada de `JWT_SECRET` via HKDF). Lockout progressivo
  independente por fator.
- **Gerador de senhas** — parâmetros configuráveis (length, símbolos).
- **Busca** — sobre `title`/`site` (claro) server-side.
- **Health Dashboard** (`/health`) — score 0–100 do cofre; detecta senhas
  fracas (comprimento/comum/só-letras/só-dígitos), reutilizadas e antigas.
  Análise 100% client-side; servidor persiste só contagens agregadas. Ver
  `docs/features/health-dashboard.md` e roadmap de **breach check local
  via HIBP offline**.
- **Auditor/security headers** — CSP, `X-Frame-Options`, `Referrer-Policy`,
  `Permissions-Policy` restritivas. Ver `docs/deployment/csp.md`.

## Roadmap (RFC ativa)

Fases documentadas em `docs/superpowers/specs/2026-09-23-forgot-password-rfc.md`:

| Fase | Entrega | Status |
|---|---|---|
| 1 | MFA local (TOTP) | ✅ merge em progresso |
| 2 | Recovery key + reset destrutivo com token | 🟡 RFC aprovada |
| 3 | Google OIDC como identidade (opcional) | 🟡 RFC aprovada |
| 4 | WebAuthn / biometria móvel | 🟡 RFC aprovada |
| 5 | Breach check local (HIBP offline) | 📋 spec em `health-dashboard.md §9` |

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

Estado atual: **78/78 backend**, **21/21 frontend**.

## Backup

```bash
make backup
```

Dump compactado em `backups/`. Como o cofre é zero-knowledge, o backup contém
apenas ciphertext — sem a senha-mestra + recovery key, não há como restaurar.

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
