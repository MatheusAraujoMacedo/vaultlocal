# VaultLocal — ZK database cutover

Este procedimento é para bancos criados antes do modelo zero-knowledge.

## O que o cutover faz

A migration `51459a466ecc_zero_knowledge_entries` encerra o modelo antigo e
prepara o schema para o modelo client-side:

- apaga `users`, `sessions` e `vault_entries`;
- aplica as migrations seguintes;
- cria os campos de envelope ZK;
- preserva a execução normal bloqueando automaticamente bancos pré-ZK com dados.

O corte é **destrutivo** para os dados existentes. Não existe migração
criptográfica in-place do material de chave do modelo antigo.

## Procedimento seguro

Primeiro, suba apenas o Postgres:

```bash
docker compose up -d db
```

Gere um dump:

```bash
make backup
```

Valide o arquivo:

```bash
gzip -t backups/<arquivo>.sql.gz
```

Execute o corte somente com confirmação explícita:

```bash
CONFIRM=YES BACKUP=backups/<arquivo>.sql.gz make cutover-zk
```

Depois valide:

```bash
docker compose run --rm --no-deps api alembic current
docker compose exec -T db psql -U vault -d vaultdb -Atc \
  "select 'users',count(*) from users union all
   select 'vault_entries',count(*) from vault_entries union all
   select 'sessions',count(*) from sessions"
```

O resultado esperado após o corte é:

```text
004_crypto_aad_v2 (head)
users|0
vault_entries|0
sessions|0
```

Por fim:

```bash
docker compose up -d --wait
curl -fsS http://127.0.0.1:8080/ >/dev/null
```

## Rollback

Rollback significa restaurar o dump em uma instância limpa do Postgres. Não
é uma operação de downgrade da migration, porque o dump contém o estado
pré-ZK e o downgrade do schema não reconstrói as chaves nem os dados perdidos
pelo cutover.

Nunca execute o cutover sem um backup validado.
