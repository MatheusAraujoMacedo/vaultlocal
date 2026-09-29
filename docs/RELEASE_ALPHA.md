# VaultLocal 0.2.0-alpha.1

## Objetivo da release

Esta release demonstra a arquitetura local-first/zero-knowledge e reúne os
fluxos de autenticação, proteção do cofre, análise de segurança e recuperação.

## Estado atual

### Implementado

- [x] TOTP + lockout progressivo
- [x] Recovery Key + prova ECDSA
- [x] Google OIDC + PKCE
- [x] WebAuthn/passkey + múltiplos dispositivos
- [x] Login local com passkey
- [x] Auto Lock
- [x] Exportação/importação cifrada
- [x] Security Timeline
- [x] Lixeira segura com restauração e retenção de 30 dias
- [x] Health Dashboard
- [x] HIBP online por k-anonymity
- [x] Adapter para HIBP offline
- [x] Corpus HIBP completo importado e E2E local validado

### Em desenvolvimento

As próximas evoluções do produto estão em desenvolvimento contínuo. O roadmap
público permanece intencionalmente de alto nível para preservar decisões de
produto e detalhes de implementação.

## Validação do corpus HIBP local

O corpus SHA-1 local foi validado com 1.048.576 ranges e um fixture conhecido
(password). Use make hibp-validate-local para repetir a validação.

## Qualidade técnica

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
