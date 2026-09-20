up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

backup:
	@mkdir -p backups
	docker compose exec -T db pg_dump -U vault vaultdb | gzip > backups/vault-$$(date +%Y%m%d-%H%M%S).sql.gz
	@echo "Backup criado em backups/"

restore:
	@echo "Use: gunzip -c backups/arquivo.sql.gz | docker compose exec -T db psql -U vault vaultdb"

dev-backend:
	cd backend && ../.venv/bin/uvicorn app.main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

migrate:
	cd backend && ../.venv/bin/alembic upgrade head

revision:
	cd backend && ../.venv/bin/alembic revision --autogenerate -m "$(m)"

test:
	cd backend && ../.venv/bin/python -m pytest -q

test-backend:
	cd backend && ../.venv/bin/python -m pytest -q

test-frontend:
	cd frontend && npm test
