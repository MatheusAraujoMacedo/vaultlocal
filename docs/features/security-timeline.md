# Security Timeline

A Security Timeline registra apenas eventos de segurança e administração do cofre.

## Privacidade

O evento não armazena título, site, usuário, senha, notas, tags ou qualquer
payload criptografado da entrada. O registro contém somente o tipo do evento,
o usuário proprietário e o timestamp.

## Eventos atuais

- entrada adicionada, atualizada ou removida
- auditoria de segurança executada
- passkey adicionada, renomeada ou revogada
- senha-mestra alterada
- MFA ativado
- Recovery Key utilizada

## API

`GET /api/v1/health/timeline?limit=100`

A resposta é sempre filtrada pelo usuário autenticado. O limite aceito é de
1 a 100 eventos por consulta.

## Armazenamento

Os eventos ficam em `security_events`, com exclusão em cascata quando o
usuário é removido. A migração atual é `011_security_events`.

## Objetivo

A Timeline fornece rastreabilidade sem transformar o servidor em um diário
de conteúdo sensível. Ela complementa o Health Dashboard e serve como base
para futuras funções de auditoria, alertas e histórico de segurança.
