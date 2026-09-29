# VaultLocal

Status de release: **0.2.0-alpha.1** — alpha técnico, local-first, com foco em segurança.

**CI:** backend + frontend + Docker, com testes, lint, auditoria de dependências, typecheck, build e smoke test.

> **Estado do Alpha:** suíte local validada com **119 testes backend + 43 testes frontend**, TypeScript, build de produção, Ruff, `pip-audit`, `npm audit` e validação do corpus HIBP offline completo. O projeto é um Alpha técnico para demonstração e feedback; não substitui uma auditoria de segurança independente.

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
- **Auto Lock** — após 5 minutos sem atividade, o cliente encerra a sessão, limpa a
  KEK mantida em memória e exige nova autenticação.
- **Exportação/importação cifrada** — transferência portátil protegida no navegador
  por senha independente, Argon2id + AES-256-GCM. O arquivo exportado não contém
  segredos em claro e as importações são recriptografadas sob a KEK do cofre atual.
- **Security Timeline** — histórico de eventos administrativos e de segurança, sem registrar segredos, tokens ou conteúdo das entradas.
- **Lixeira segura** — entradas excluídas deixam de aparecer no cofre e permanecem cifradas por 30 dias para restauração; a exclusão permanente é explícita.
- **Expiração de credenciais** — metadado opcional por entrada, visível no cofre e filtrável no Health Dashboard.
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

Segurança e modelo de ameaça: consulte **SECURITY.md** e **docs/deployment/hardening.md**.

## Release e qualidade

A branch `main` recebe uma suíte de CI que valida três áreas: backend, frontend e Docker. A verificação local equivalente é `make verify`.

O projeto segue um modelo **local-first / zero-knowledge**: recursos online são opcionais quando explicitamente configurados, enquanto o Health Dashboard pode usar o corpus HIBP local sem enviar o hash completo da senha ao serviço externo.

## Roadmap

O produto segue em **desenvolvimento contínuo**. Funcionalidades futuras, decisões
de produto e detalhes de implementação são mantidos fora da documentação pública
detalhada. O foco atual é evolução incremental, validação de segurança, qualidade
de código e melhoria da experiência local-first.

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
make verify         # suíte completa + build + Ruff + HIBP local
```

Validação do corpus HIBP offline (não versionado no Git):
```bash
make hibp-validate-local       # valida os 1.048.576 ranges e fixture conhecido
make hibp-index-rebuild-local  # reconstrói o índice local se ele for perdido
```

O corpus `data/hibp/sha1/` é mantido fora do Git por tamanho. Ele contém 1.048.576 ranges SHA-1 e é montado como somente leitura no container da API.

Estado atual da suíte: **119/119 backend**, **43/43 frontend** + TypeScript, build de produção, Ruff e migração Alembic validados.

## Backup

```bash
make backup
```

Dump compactado em `backups/`. Os segredos do cofre permanecem como ciphertext,
mas o arquivo ainda contém metadados e hashes de autenticação. A exportação
portátil cifrada ponta a ponta é processada exclusivamente no cliente; o servidor
não recebe o arquivo exportado nem a senha usada para protegê-lo.

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
Para a discussão de ameaças e hardening: docs/deployment/csp.md e docs/deployment/hardening.md.

## Licença

MIT (ver `LICENSE` se presente).
