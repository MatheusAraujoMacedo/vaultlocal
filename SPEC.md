# Spec — Cofre de Senhas Local (codinome: VaultLocal)

## 1. Visão Geral

Gerenciador de senhas self-hosted, rodando 100% local via Docker Compose.
Senhas criptografadas no cliente/servidor com chave derivada da senha-mestra do
usuário (zero-knowledge): o banco nunca armazena nada em texto plano nem a chave
de descriptografia.

Acesso somente via rede local (bind em 127.0.0.1 por padrão).

## 2. Objetivos e Não-Objetivos

### Objetivos
- Cadastro de usuários, cada um com seu cofre isolado.
- CRUD de entradas de senha (título, site, usuário, senha, notas, tags).
- Criptografia forte (AES-256-GCM) com chave derivada via Argon2id.
- Tudo roda com `docker compose up` — uma única command line.
- Backup simples (dump do volume ou export criptografado).

### Não-Objetivos (v1)
- Extensão de navegador / autofill.
- App mobile.
- Compartilhamento de senhas entre usuários.
- SSO / OAuth.
- Sync em nuvem (Render) — fase 2, opt-in.

## 3. Arquitetura

```
┌─────────────────────────────────────────────────┐
│                 Docker Compose                  │
│                                                 │
│  ┌───────────┐     ┌───────────┐   ┌────────┐   │
│  │ Frontend  │────▶│  API      │──▶│Postgres│   │
│  │ (SPA)     │     │ (FastAPI) │   │  16    │   │
│  │ Nginx     │     │  Python   │   │ volume │   │
│  └───────────┘     └───────────┘   └────────┘   │
│   :8080 (127.0.0.1)  :8000 (interno)  :5432     │
│                      (não exposto)   (não exp.) │
└─────────────────────────────────────────────────┘
```

**Decisão de criptografia (importante):** criptografia no BACKEND por simplicidade
na v1, com a chave derivada da senha-mestre mantida apenas em memória durante a
sessão (nunca persistida). Evolução natural: mover a derivação para o frontend
(zero-knowledge real) — documentado na seção 10.

## 4. Stack

| Camada      | Escolha                          | Motivo                                   |
|-------------|----------------------------------|------------------------------------------|
| Banco       | PostgreSQL 16 (Alpine)           | Robusto, volume Docker persiste local    |
| Backend     | Python 3.12 + FastAPI            | Rápido de escrever, ótimo p/ API REST    |
| Auth        | JWT (access 15min + refresh 7d)  | Stateless, padrão                        |
| KDF         | Argon2id (via `argon2-cffi`)     | Resistente a GPU/ASIC, padrão atual      |
| Cripto      | AES-256-GCM (via `cryptography`) | AEAD, autenticado                        |
| Frontend    | React + Vite + Tailwind          | SPA leve servida por Nginx               |
| Proxy       | Nginx                            | Serve o frontend e faz proxy /api        |
| Orquestração| Docker Compose v2                | Um comando sobe tudo                     |

## 5. Criptografia

### 5.1 Derivação de chave
```
master_password (usuário digita no login)
       │
       ▼
KEK = Argon2id(master_password, salt_unico_por_usuario,
               time_cost=3, memory=64MB, parallelism=2)
```
- `salt` gerado por usuário no registro (16 bytes, aleatório), armazenado em claro.
- A KEK nunca é salva. Fica em memória no servidor apenas durante a sessão
  (associada ao token de sessão, com TTL). Alternativa mais segura: reenviar a
  KEK (ou um wrapped key) a cada request — ver trade-offs na seção 10.

### 5.2 Senhas armazenadas
```
Para cada entrada de senha:
  data_key = chave aleatória de 32 bytes (por entrada)
  ciphertext = AES-256-GCM(data_key, senha_plaintext, aad=user_id+entry_id)
  wrapped_data_key = AES-256-GCM(KEK, data_key)
  Banco guarda: ciphertext, nonce, wrapped_data_key, wrapped_nonce
```
Envelope encryption por entrada: rotacionar a senha-mestra exige re-encriptar
só as data_keys, não todos os segredos.

### 5.3 Hash de autenticação
A senha-mestra também serve para login. Para não confundir os dois usos:
- Login: `Argon2id(master_password + salt_auth)` → hash verificado no servidor.
- Cripto: `Argon2id(master_password + salt_crypto)` → KEK.
Salts diferentes = chaves diferentes, um não revela o outro.

## 6. Modelo de Dados (PostgreSQL)

```sql
users (
  id            UUID PK,
  email         TEXT UNIQUE NOT NULL,
  auth_hash     TEXT NOT NULL,          -- Argon2id, p/ login
  salt_auth     BYTEA NOT NULL,
  salt_crypto   BYTEA NOT NULL,         -- p/ derivar KEK
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
)

vault_entries (
  id            UUID PK,
  user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
  title         TEXT NOT NULL,          -- NÃO criptografado (trade-off: busca)
  site          TEXT,
  username_enc  BYTEA NOT NULL,
  password_enc  BYTEA NOT NULL,
  notes_enc     BYTEA,
  nonce_user    BYTEA NOT NULL,
  nonce_pass    BYTEA NOT NULL,
  nonce_notes   BYTEA,
  tags          TEXT[] DEFAULT '{}',
  created_at    TIMESTAMPTZ DEFAULT now(),
  updated_at    TIMESTAMPTZ DEFAULT now()
)

sessions (
  id            UUID PK,
  user_id       UUID REFERENCES users(id) ON DELETE CASCADE,
  refresh_hash  TEXT NOT NULL,
  expires_at    TIMESTAMPTZ NOT NULL,
  created_at    TIMESTAMPTZ DEFAULT now()
)
```

Nota: `title`/`site` em claro permite busca; se quiser zero-knowledge total,
criptografe tudo e perca busca server-side (decisão registrada).

## 7. API (FastAPI)

Base: `/api/v1`

### Auth
| Método | Rota                | Descrição                              |
|--------|---------------------|----------------------------------------|
| POST   | /auth/register      | Cria usuário (gera salts, auth_hash)   |
| POST   | /auth/login         | Retorna access+refresh JWT             |
| POST   | /auth/refresh       | Renova access token                    |
| POST   | /auth/logout        | Revoga refresh token                   |

### Cofre (requer access token + KEK na sessão)
| Método | Rota                | Descrição                              |
|--------|---------------------|----------------------------------------|
| GET    | /entries            | Lista entradas (sem descriptografar)   |
| POST   | /entries            | Cria entrada (criptografa no server)   |
| GET    | /entries/{id}       | Retorna entrada DESCRIPTOGRAFADA       |
| PUT    | /entries/{id}       | Atualiza (re-criptografa)              |
| DELETE | /entries/{id}       | Remove                                 |
| GET    | /entries/search?q=  | Busca por título/site                  |
| POST   | /entries/generate   | Gera senha forte (params: len, símbolos)|

### Utilidades
| Método | Rota                | Descrição                              |
|--------|---------------------|----------------------------------------|
| GET    | /health             | Healthcheck                            |
| POST   | /backup/export      | Export criptografado (.json.enc)       |

## 8. Infraestrutura (Docker)

### 8.1 docker-compose.yml (estrutura)
```yaml
services:
  db:
    image: postgres:16-alpine
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: vault
      POSTGRES_PASSWORD: ${DB_PASSWORD}   # do .env, fora do git
      POSTGRES_DB: vaultdb
    # SEM ports: — inacessível fora da rede do compose
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U vault"]

  api:
    build: ./backend
    environment:
      DATABASE_URL: postgresql://vault:${DB_PASSWORD}@db:5432/vaultdb
      JWT_SECRET: ${JWT_SECRET}
    depends_on:
      db:
        condition: service_healthy
    expose: ["8000"]          # só para o nginx

  web:
    build: ./frontend
    ports:
      - "127.0.0.1:8080:80"   # bind explícito em localhost
    depends_on: [api]

volumes:
  pgdata:
```

### 8.2 Nginx
- `location /` → arquivos estáticos do build React.
- `location /api/` → proxy_pass `http://api:8000`.
- Headers de segurança: `X-Frame-Options: DENY`, `X-Content-Type-Options:
  nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` restritiva
  e **CSP** restritiva — detalhes e justificativas em
  `docs/deployment/csp.md`. Nota: `script-src` inclui `'wasm-unsafe-eval'`
  por causa do Argon2id (hash-wasm).

### 8.3 .env (gitignored)
```
DB_PASSWORD=<senha do postgres gerada no setup>
JWT_SECRET=<64 hex chars>
```

## 9. Segurança — Requisitos e Políticas

1. Bind apenas em 127.0.0.1 (mudar exige editar o compose conscientemente).
2. Postgres e API nunca expostos na porta do host.
3. Rate limit no /auth/login (ex: 5 tentativas/min por IP) — proteção brute-force.
4. Lockout progressivo após N falhas de login.
5. Senha-mestra mínima: 12 caracteres, checagem contra lista de senhas vazadas comuns.
6. HTTPS: dispensável em 127.0.0.1; se abrir para LAN, obrigatório via cert self-signed ou Caddy.
7. Logs: nunca logar senha-mestra, KEK, ou plaintext de entradas.
8. .env no .gitignore desde o commit 1.
9. Backup: script `make backup` → `pg_dump` compactado e criptografado com a senha-mestra.
10. Clipboard: frontend limpa área de transferência 30s após copiar senha.

## 10. Alternativa: Banco no Render (fase 2, opcional)

Se quiser o Postgres gratuito do Render em vez do container local:

**O que muda:**
- Remove o serviço `db` do compose; `DATABASE_URL` aponta para a URL externa do Render.
- TLS obrigatório na conexão (`?sslmode=require`).

**Trade-offs (documentados, não bloqueantes):**
- (+) Acesso ao cofre de qualquer máquina que rode o Docker.
- (+) Não precisa cuidar de backup local (Render tem snapshots).
- (−) Ciphertext viaja/fica na nuvem — quebra o princípio "só local".
- (−) Free tier do Render expira o Postgres após 90 dias (precisa upgrade ou migração).
- (−) Latência e dependência de internet.

**Mitigação se for por esse caminho:** mover a criptografia para o frontend
(zero-knowledge real): a KEK nunca sai do navegador, o servidor só vê blobs
opacos. Nesse modelo o servidor em nuvem comprometido não expõe nada legível.

## 11. Estrutura de Repositório

```
vaultlocal/
├── docker-compose.yml
├── .env.example
├── .gitignore
├── Makefile                  # up, down, backup, restore, test
├── README.md
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt      # fastapi, uvicorn, argon2-cffi, cryptography,
│   │                         # sqlalchemy, alembic, asyncpg, pyjwt, slowapi
│   ├── app/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── db.py
│   │   ├── models/           # user.py, entry.py, session.py
│   │   ├── routers/          # auth.py, entries.py, backup.py
│   │   ├── core/             # crypto.py, security.py, deps.py
│   │   └── schemas/          # pydantic schemas
│   └── tests/
├── frontend/
│   ├── Dockerfile            # build vite → nginx
│   ├── nginx.conf
│   └── src/
│       ├── pages/            # Login, Register, Vault, EntryDetail
│       ├── components/
│       └── api/client.ts
└── scripts/
    ├── backup.sh
    └── restore.sh
```

## 12. Plano de Implementação (marcos)

| Marco | Entrega                                              | Critério de aceite                  |
|-------|------------------------------------------------------|-------------------------------------|
| M1    | Compose com Postgres + API /health                   | `compose up` sobe, /health retorna 200 |
| M2    | Auth completo (register/login/refresh) + Argon2id    | Testes de auth passam               |
| M3    | CRUD de entradas com envelope encryption             | Banco contém só ciphertext; get retorna plaintext |
| M4    | Frontend: login + lista + detalhe + gerador de senha | Fluxo completo no navegador         |
| M5    | Backup/restore, busca, lockout, clipboard-clear      | Checklist de segurança seção 9      |
| M6    | (Opcional) Migrar para Render + cripto no frontend   | Zero-knowledge E2E                  |

### Health Dashboard (pós-M6)

Painel `/health` que pontua a higiene das senhas do cofre (fracas, reutilizadas,
antigas) com análise 100% client-side sobre os segredos já descriptografados —
o servidor só persiste contagens agregadas (1 relatório por usuário, upsert).
Detalhes de arquitetura, regras, fórmula do score e cortes de MVP em
`docs/features/health-dashboard.md`.

## 13. Riscos

| Risco                                          | Mitigação                                   |
|------------------------------------------------|---------------------------------------------|
| Esquecer a senha-mestra = perder tudo          | Aviso explícito no registro; kit de recuperação exportável |
| KEK em memória no servidor (v1)                | Migrar p/ cripto no frontend (M6)           |
| Volume Docker apagado sem backup               | `make backup` documentado + lembrete        |
| JWT_SECRET fraco/vazado                        | Gerado aleatório no setup, gitignored       |
