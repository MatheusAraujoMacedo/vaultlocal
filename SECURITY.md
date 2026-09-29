# VaultLocal Security

VaultLocal é um projeto local-first de cofre de senhas com foco em zero-knowledge.
O projeto está sendo preparado para publicação como alpha/beta técnica, não como
produto submetido a auditoria de segurança independente.

## Modelo de ameaça

O objetivo principal é impedir que o banco ou a API tenham acesso aos segredos
do cofre em claro. A senha-mestra é processada no navegador e gera derivados
independentes para autenticação e proteção criptográfica.

A KEK permanece no cliente durante a sessão. Cada entrada possui uma data key
própria, e o backend armazena somente envelopes/ciphertexts e os metadados
necessários para funcionalidades como busca.

## Controles

- Argon2id para KDF e hashes de autenticação.
- AES-256-GCM com integridade autenticada.
- AAD na versão criptográfica vigente.
- TOTP com lockout progressivo.
- Recovery Key com prova ECDSA P-256.
- WebAuthn/passkeys com user verification e PRF para acesso confiável.
- Rotação de refresh token e sessões revogáveis.
- Auto Lock client-side.
- Health Dashboard com análise de senha no navegador.
- HIBP com k-anonymity online ou corpus local.
## Limites importantes

Zero-knowledge não protege contra um cliente comprometido. Se o JavaScript
entregue ao navegador for adulterado, ele pode observar a senha-mestra ou
segredos enquanto estão sendo usados. Por isso o projeto também aplica CSP,
controle de dependências, headers defensivos e bind local por padrão.

O backend conhece alguns metadados por decisão de produto, principalmente
título, site e tags. Esses dados permitem busca sem descriptografar o cofre,
mas não são considerados totalmente confidenciais.

O projeto não declara conformidade com ISO 27001, SOC 2, OWASP ASVS ou qualquer
certificação. Esses frameworks podem orientar etapas futuras, mas não são
evidência de segurança por si mesmos.

## Reporte responsável

Para problemas de segurança encontrados no projeto, registre uma issue privada
ou utilize um canal de contato definido pelo mantenedor antes de publicar
detalhes de exploração. Não inclua senhas reais, tokens, recovery keys ou
backups contendo material sensível.

## Ambiente de demonstração

Use somente credenciais de teste. Nunca coloque senhas pessoais, tokens de
produção ou secrets reutilizados no repositório, em screenshots ou em vídeos.
