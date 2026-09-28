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
- API sem cache; query strings não entram nos access logs do Nginx.
- Uvicorn sem access log duplicado.
- OpenAPI/Swagger/ReDoc desabilitados em produção.
- Docker exige secrets fortes via Compose.
- CI executa testes, typecheck, build e auditoria de dependências.

## Estado de validação

- Backend: 78 testes.
- Frontend: 21 testes.
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
