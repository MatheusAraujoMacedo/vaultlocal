# VaultLocal

Gerenciador de senhas self-hosted, 100% local, com Docker.

## Requisitos
- Docker com compose v2
- (para dev local) Node 20+ e Python 3.12+

## Subir tudo

```bash
cp .env.example .env
# edite .env: defina DB_PASSWORD e JWT_SECRET fortes
docker compose up -d --build
```

Acesse http://127.0.0.1:8080

## Features

- CRUD de entradas com criptografia zero-knowledge no frontend (AES-256-GCM + Argon2id)
- Gerador de senhas fortes
- Busca por título/site
- Health Dashboard (`/health`): score 0-100 do cofre, detecção de senhas fracas/reutilizadas/antigas — ver `docs/features/health-dashboard.md`

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

Acesse http://127.0.0.1:5173 (proxy /api → :8000 já configurado).

## Backup

```bash
make backup
```
Cria dump compactado em `backups/`.

## Segurança

- Senhas cifradas com AES-256-GCM. Chave derivada via Argon2id a partir da senha-mestra.
- A chave de criptografia nunca é persistida — apenas em memória durante a sessão.
- Esquecer a senha-mestra = perder o cofre. Não há recuperação.
- Por padrão o serviço só escuta em 127.0.0.1.

Veja SPEC.md para arquitetura completa.
