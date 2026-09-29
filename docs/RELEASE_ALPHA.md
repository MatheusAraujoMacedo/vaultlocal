# VaultLocal 0.2.0-alpha.1

## Objetivo da release

Esta release demonstra a arquitetura local-first/zero-knowledge e reúne os
fluxos de autenticação, proteção do cofre, análise de segurança e recuperação.

## Checklist funcional

- [x] TOTP + lockout progressivo
- [x] Recovery Key + prova ECDSA
- [x] Google OIDC + PKCE
- [x] WebAuthn/passkey + múltiplos dispositivos
- [x] Login local com passkey
- [x] Auto Lock
- [x] Exportação/importação cifrada
- [x] Security Timeline
- [x] Health Dashboard
- [x] HIBP online por k-anonymity
- [x] Adapter para HIBP offline
- [x] Corpus HIBP completo importado e E2E local validado

### Validação do corpus HIBP local

O corpus SHA-1 local foi validado com 1.048.576 ranges e um fixture conhecido (`password`).
Use `make hibp-validate-local` para repetir a validação. Se o arquivo `sha1.index` for perdido, `make hibp-index-rebuild-local` pode reconstruir um índice local de prontidão após confirmar que todos os ranges estão presentes. Esse índice usa marcadores `LOCAL`; ele não representa ETags HTTP do downloader oficial.

## Checklist técnico

- [x] 119 testes backend
- [x] 43 testes frontend
- [x] TypeScript
- [x] Build Vite
- [x] Ruff
- [x] Docker Compose
- [x] Alembic
- [x] Security headers + CSP
- [x] Trusted Host + CORS restritivo
- [x] SECURITY.md + modelo de ameaça

## Limite da release

Alpha técnico para demonstração e feedback. Não é uma auditoria independente
nem uma declaração de prontidão para produção pública.
