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

cutover-zk:
	@BACKUP="$(BACKUP)" CONFIRM="$(CONFIRM)" ./scripts/cutover-zk.sh

dev-backend:
	cd backend && ../.venv/bin/uvicorn app.main:app --reload --port 8000

dev-frontend:
	cd frontend && npm run dev

migrate:
	cd backend && ../.venv/bin/alembic upgrade head

revision:
	cd backend && ../.venv/bin/alembic revision --autogenerate -m "$(m)"

HIBP_DOWNLOADER ?= $(HOME)/.dotnet/tools/haveibeenpwned-downloader

hibp-download:
	@mkdir -p data/hibp/sha1
	@test -x "$(HIBP_DOWNLOADER)" || (echo "Instale haveibeenpwned-downloader (.NET 10+): https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader" && exit 1)
	"$(HIBP_DOWNLOADER)" data/hibp/sha1 --max-retries 5 $(if $(P),-p $(P),)

hibp-index-ready:
	@test -f data/hibp/sha1/sha1.index
	@test -s data/hibp/sha1/sha1.index
	@echo "Índice HIBP local disponível."

hibp-index-rebuild-local:
	@python3 scripts/rebuild_hibp_index.py

hibp-validate-local:
	@python3 scripts/validate_hibp_local.py

test:
	cd backend && ../.venv/bin/python -m pytest -q

test-backend:
	cd backend && ../.venv/bin/python -m pytest -q

test-frontend:
	cd frontend && npm test
