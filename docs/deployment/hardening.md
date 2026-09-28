# VaultLocal — Hardening Baseline

Esta fase congela as implementações de produto e prioriza segurança,
integridade e reprodutibilidade.

## Controles implementados

- Argon2id para autenticação e derivação de KEK.
- AES-256-GCM com envelope encryption por entrada.
- Crypto v1 legado preservado para leitura; crypto v2 usa AAD vinculado ao
  `entry_id` e aos metadados do campo.
- MFA TOTP e lockout progressivo.
- `JWT_SECRET` separado de `TOTP_ENCRYPTION_KEY`.
- Access tokens vinculados a sessões revogáveis (`sid`).
- Rate limit nas superfícies de autenticação.
- Gerador de senhas executado somente no cliente com Web Crypto.
- Backend executado como usuário não-root no container.
- CORS de desenvolvimento não é habilitado em produção.
- Frontend não carrega fontes ou estilos externos; reduzimos dependência e vazamento de metadados para terceiros.
- API sem cache; query strings não entram nos access logs do Nginx.
- Uvicorn sem access log duplicado.
- OpenAPI/Swagger/ReDoc desabilitados em produção.
- Docker exige secrets fortes via Compose.
- CI executa lint, testes, typecheck, build e auditoria de dependências.

## Segurança de migração

A migration `51459a466ecc` é o corte do modelo antigo de criptografia para o modelo
zero-knowledge atual. Ela é deliberadamente destrutiva para bancos pré-ZK e
recusa execução quando já existem usuários, a menos que uma flag explícita seja
fornecida. Durante o hardening essa flag **não** foi usada e nenhum dado do
volume existente foi apagado.

O procedimento de migração/reset desse volume deve ser tratado como uma
operação controlada separada do startup normal, com backup e validação prévios.
O runbook detalhado está em `docs/deployment/zk-cutover.md`.

## Estado de validação

- Backend: 80 testes.
- Frontend: 23 testes.
- Validação isolada dos testes não depende do `.env` local.
- Limites de entrada aplicados aos principais payloads e buscas autenticadas.
- API possui healthcheck próprio; o frontend só sobe após a API estar saudável.
- TypeScript: OK.
- Build Vite: OK.
- `pip-audit`: sem vulnerabilidades conhecidas.
- `npm audit`: sem vulnerabilidades moderadas ou superiores.
- Migration head: `004_crypto_aad_v2`.

## Secrets do ambiente local

O `JWT_SECRET` local foi rotacionado para 64 caracteres hexadecimais e uma
`TOTP_ENCRYPTION_KEY` independente de 64 caracteres hexadecimais foi criada.
As sessões existentes foram revogadas durante a rotação. O banco atual não
possuía segredos TOTP armazenados no momento da rotação, portanto nenhuma
credencial TOTP precisou ser recriptografada.

Não reutilize as chaves deste ambiente em outros ambientes.
