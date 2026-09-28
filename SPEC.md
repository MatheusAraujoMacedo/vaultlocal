# Spec — Cofre de Senhas Local (codinome: VaultLocal)

> **Governança & Princípio Central:**  
> Todas as decisões de arquitetura, implementação e priorização técnica devem passar pelas diretrizes estabelecidas no documento de visão estratégica: [docs/VISAO_ESTRATEGICA.md](file:///home/matheusaraujosami/Documentos/vaultlocal/docs/VISAO_ESTRATEGICA.md).

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

**Decisão de criptografia (vigente):** derivação de chave e criptografia de dados
ocorrem no FRONTEND. A senha-mestra nunca é enviada ao backend; a KEK e as
`data_key`s permanecem no cliente e o servidor recebe apenas material criptografado
e metadados explicitamente necessários para busca.

O frontend deriva duas chaves independentes via Argon2id: uma `auth_key` usada
apenas para autenticação e uma KEK usada para proteger as `data_key`s. A KEK é
mantida em memória como `CryptoKey` não-extraível durante a sessão.

## 4. Stack

| Camada      | Escolha                          | Motivo                                   |
|-------------|----------------------------------|------------------------------------------|
| Banco       | PostgreSQL 16 (Alpine)           | Robusto, volume Docker persiste local    |
| Backend     | Python 3.12 + FastAPI            | Rápido de escrever, ótimo p/ API REST    |
| Auth        | JWT + sessões (access 15min + refresh 7d) | Access token vinculado a sessão revogável |
| KDF         | Argon2id (via `argon2-cffi`)     | Resistente a GPU/ASIC, padrão atual      |
| Cripto      | AES-256-GCM (via `cryptography`) | AEAD, autenticado                        |
| Frontend    | React + Vite + Tailwind          | SPA leve servida por Nginx               |
| Proxy       | Nginx                            | Serve o frontend e faz proxy /api        |
| Orquestração| Docker Compose v2                | Um comando sobe tudo                     |

## 5. Criptografia

### 5.1 Derivação de chaves no cliente
```
master_password (digitada no navegador)
       │
       ├── Argon2id(master_password, salt_auth)
       │          └── auth_key → enviado ao backend para verificação/hash
       │
       └── Argon2id(master_password, salt_crypto)
                  └── KEK (CryptoKey não-extraível, apenas no cliente)
```

- `salt_auth` e `salt_crypto` são aleatórios e independentes, gerados no cliente.
- A senha-mestra, a KEK e qualquer segredo em claro do cofre nunca são enviados
  ao backend.
- A `auth_key` é um derivado da senha, não a senha em si; o backend armazena
  somente seu hash Argon2id para autenticação.

### 5.2 Envelope encryption por entrada

O formato criptográfico é versionado para permitir endurecimento sem perder
compatibilidade com cofres criados antes da adoção de AAD.

| Versão | Estado | Proteção |
|---|---|---|
| `1` | legado | AES-256-GCM sem AAD |
| `2` | vigente | AES-256-GCM com AAD vinculando registro/metadados |

Para uma entrada v2:
```
data_key = AES-256-GCM key aleatória por entrada
wrapped_data_key = AES-256-GCM(KEK, data_key, AAD=data-key(entry_id))
username_enc = AES-256-GCM(data_key, username, AAD=field(entry_id,title,site,"username"))
password_enc = AES-256-GCM(data_key, password, AAD=field(entry_id,title,site,"password"))
notes_enc    = AES-256-GCM(data_key, notes,    AAD=field(entry_id,title,site,"notes"))
```

A criação gera o `entry_id` no cliente antes de cifrar, pois ele participa do
AAD. Alterar título/site ou mover ciphertext/wrapped key entre IDs faz a
descriptografia falhar por violação da tag GCM. A AAD da `data_key` usa somente
o `entry_id` para que fluxos futuros de recovery/password rotation consigam
re-encapsular a chave sem precisar descriptografar os campos ou conhecer
metadados.

Entradas v1 permanecem legíveis sem AAD. Ao editar uma entrada v1, o frontend
a descriptografa usando o formato legado e salva novamente como v2.

A criptografia e a descriptografia acontecem no navegador. O backend apenas
persiste e recupera blobs criptografados. A rotação da senha-mestra troca a
proteção das `data_key`s sem recriptografar os campos do cofre.

### 5.3 Integridade e limites de confiança

AES-256-GCM fornece confidencialidade e integridade autenticada dos blobs. A
segurança zero-knowledge depende também da integridade do cliente que executa a
criptografia: um servidor que consiga substituir o JavaScript entregue ao
navegador pode, em princípio, capturar uma senha-mestra no momento do uso. Por
isso, deploy, CSP, supply-chain e integridade dos artefatos fazem parte do
modelo de ameaça e ficam fora da promessa de que "criptografia sozinha" impede
um cliente comprometido de exfiltrar segredos.

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
  crypto_version SMALLINT NOT NULL DEFAULT 1, -- 1=legacy, 2=AAD
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

### Cofre (requer access token; descriptografia ocorre no cliente)
| Método | Rota                | Descrição                              |
|--------|---------------------|----------------------------------------|
| GET    | /entries            | Lista entradas (sem descriptografar)   |
| POST   | /entries            | Persiste entrada já criptografada no cliente |
| GET    | /entries/{id}       | Retorna os blobs criptografados       |
| PUT    | /entries/{id}       | Persiste atualização já criptografada |
| DELETE | /entries/{id}       | Remove                                 |
| GET    | /entries/search?q=  | Busca por título/site                  |

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
DB_PASSWORD=<64 hex chars>
JWT_SECRET=<64 hex chars>
TOTP_ENCRYPTION_KEY=<64 hex chars>
```

## 9. Segurança — Requisitos e Políticas

1. Bind apenas em 127.0.0.1 (mudar exige editar o compose conscientemente).
2. Postgres e API nunca expostos na porta do host.
3. Rate limit nas superfícies de autenticação (`login/init`, `register`, `login`, `refresh`, `mfa/verify`, `totp/confirm`).
4. Lockout progressivo após N falhas de login.
5. Senha-mestra mínima: 12 caracteres, checagem contra lista de senhas vazadas comuns.
6. HTTPS: dispensável em 127.0.0.1; se abrir para LAN, obrigatório via cert self-signed ou Caddy.
7. Logs: nunca logar senha-mestra, KEK, ou plaintext de entradas.
8. JWT signing key e chave de criptografia TOTP são independentes e obrigatórias.
9. Access tokens usam `sid` e só são aceitos enquanto a sessão correspondente existir e não estiver expirada.
10. .env no .gitignore desde o commit 1.
11. Backup: script `make backup` → `pg_dump` compactado contendo apenas os blobs criptografados e metadados do banco. Não é criptografia adicional com a senha-mestra; exportação portátil cifrada deve ser implementada no cliente.
12. Clipboard: frontend limpa a área de transferência 30s após copiar senha.

## 10. Banco em nuvem (fase futura, opcional)

O PostgreSQL local pode futuramente ser substituído por um banco gerenciado.
Isso não altera o modelo criptográfico atual: o frontend já cifra os segredos e o backend persiste apenas blobs criptografados.

**O que muda:**
- `DATABASE_URL` passa a apontar para um serviço externo.
- TLS é obrigatório para conexão e transporte.
- Disponibilidade, metadados, supply-chain, logs e confiança no provedor entram no modelo de ameaça.

O princípio local-first deixa de ser absoluto, mas a confidencialidade dos segredos continua dependente de a KEK permanecer exclusivamente no cliente e de a integridade do cliente distribuído ser preservada.

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
