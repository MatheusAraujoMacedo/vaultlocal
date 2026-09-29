# VaultLocal — Visão Estratégica, Arquitetura e Roadmap

> **Documento de Referência Arquitetural e Tomada de Decisão**  
> **Autor:** Matheus Araújo Macedo  
> **Versão:** 1.0  
> **Data:** Setembro de 2026  
> **Status:** Ativo / Governança Central  

---

> [!IMPORTANT]
> **Princípio Fundamental:**  
> **O usuário deve ser o único capaz de acessar seus segredos.** Nem mesmo a infraestrutura do VaultLocal deve ser capaz de acessar o conteúdo descriptografado dos usuários. Qualquer decisão técnica ou funcional no projeto deve obedecer estritamente a este documento.

---

## 1. Introdução

O **VaultLocal** nasceu com a proposta de ser um gerenciador de credenciais focado em **privacidade, segurança e controle do usuário** sobre seus próprios dados.

Diferente de muitos cofres de senha tradicionais, o objetivo do projeto não é apenas armazenar senhas, mas oferecer uma **plataforma de segurança pessoal** capaz de identificar riscos, analisar a qualidade das credenciais e fornecer inteligência sobre a saúde digital do usuário.

---

## 2. Visão do Produto

O VaultLocal será construído seguindo uma abordagem:
* **Local First**
* **Zero-Knowledge**
* **Open Source**
* **Segurança por padrão**
* **Auditoria contínua de credenciais**

### Capacidades a Longo Prazo
* Armazenamento seguro de senhas
* Notas seguras
* Chaves de API
* Tokens
* Certificados
* Informações financeiras
* Compartilhamento seguro
* Sincronização entre dispositivos

*Tudo sem que o servidor tenha acesso ao conteúdo descriptografado.*

---

## 3. Diferencial Competitivo

A maioria dos gerenciadores de senha oferece apenas:
* Armazenamento
* Autofill
* Sincronização

O **VaultLocal** oferece uma camada ativa de inteligência:
* **Security Health Dashboard**
* **Análise contínua de:**
  * Senhas fracas
  * Senhas reutilizadas
  * Senhas antigas
  * Senhas vazadas
  * Credenciais sem MFA
  * Credenciais críticas

Transformando o cofre em uma ferramenta ativa de segurança e mitigação de postura.

---

## 4. Arquitetura Atual

| Camada | Tecnologia |
|---|---|
| **Frontend** | React, TypeScript, Vite, TailwindCSS |
| **Backend** | Python, FastAPI, SQLAlchemy, Alembic, JWT |
| **Banco de Dados** | PostgreSQL (Produção / Container) / SQLite (Desenvolvimento rápido) |
| **Infraestrutura** | Docker Compose |

---

## 5. Modelo de Segurança

### Objetivo
O servidor nunca deve possuir acesso às informações descriptografadas.

### Fluxo de Criptografia
```
Master Password
      │
      ▼
Argon2id (Derivação KEK)
      │
      ▼
KEK (Key Encryption Key)
      │
      ▼
Descriptografa Data Key
      │
      ▼
AES-256-GCM
      │
      ▼
Credenciais / Segredos
```

### Benefícios
Mesmo na ocorrência de:
* Banco de dados comprometido
* Backup roubado
* Servidor invadido

**Os dados continuam íntegros e protegidos matematicamente.**

---

## 6. Roadmap de Produto

### Fase 1 — MVP (Concluído / Em andamento)
- [x] Cadastro de usuários e login
- [x] Criptografia com derivação segura
- [x] CRUD de credenciais
- [x] Dashboard de saúde digital (Health Score)
- [x] Testes automatizados (Backend e Frontend)
- [x] Docker Compose

### Fase 2 — Segurança Avançada (Concluída)
- [x] **Auto Lock:** Bloqueio automático do cofre após período de inatividade (ex: 5 min sem atividade -> expurgar chaves da memória RAM -> exigir desbloqueio).
- [x] **Exportação Segura:** Exportação de dados cifrada ponta a ponta.
- [x] **Importação Segura:** Migração cifrada validada por testes.
- [x] **MFA:** TOTP e WebAuthn/passkeys implementados; suporte a múltiplos dispositivos.

### Fase 3 — Desktop
* **Tecnologia:** Electron (Windows, Linux, macOS)
* **Estrutura:** `Electron -> VaultLocal API Local -> Banco Local`
* **Objetivos:** Experiência nativa, funcionamento 100% offline, persistência controlada e base para integração com o SO e navegador.

### Fase 4 — Extensão Chrome (Planejada)
* **Objetivo:** Integrar o cofre de forma segura ao navegador.
* **Funcionalidades:**
  * **Autofill:** Preenchimento automático de usuário, e-mail e senha.
  * **Salvamento Inteligente:** Detecção de novos cadastros e prompts de salvamento.
  * **Gerador de Senhas:** Geração de entropia e senhas seguras no fluxo de navegação.
  * **Captura Automática:** Detecção de domínio, site e credencial.
* **Arquitetura da Extensão:**
  ```
  Chrome Extension ──▶ Local API ──▶ VaultLocal Desktop ──▶ Banco Criptografado
  ```
  *A extensão nunca armazena segredos; todo acesso é pontual e passa pelo cofre principal.*

---

## 7. Roadmap SaaS

### Objetivo
Permitir sincronização multi-dispositivo preservando o modelo Zero-Knowledge.

### Arquitetura de Nuvem
`Cloudflare ──▶ Frontend ──▶ FastAPI ──▶ PostgreSQL`

| Serviço | Provedor / Ferramenta |
|---|---|
| **Frontend** | Cloudflare Pages |
| **Backend** | Railway ou Render |
| **Banco de Dados** | Neon ou Supabase |
| **Armazenamento de Arquivos** | Cloudflare R2 |
| **E-mails Transacionais** | Resend |
| **Monitoramento** | Grafana Cloud |
| **Erros e Rastreamento** | Sentry |

---

## 8. Arquitetura Multi-Tenant

Na evolução para SaaS:
```
Tenant (Organização / Conta)
   └── Usuários
         └── Vaults (Cofres)
               └── Credenciais / Ativos
```
Todas as entidades relevantes possuirão isolamento estrito via `tenant_id`, suportando múltiplos clientes na mesma infraestrutura sem vazamento de escopo.

---

## 9. Observabilidade

### Stack Planejada
`OpenTelemetry ──▶ Grafana ──▶ Loki (Logs) + Tempo (Tracing) + Prometheus (Métricas)`

Consolidação de logs, métricas operacionais e rastreamento distribuído em uma plataforma única.

---

## 10. Integrações Futuras

* **Login Social:** Google, GitHub, Microsoft (com isolamento de chave-mestre local).
* **Pagamentos & Billing:** Stripe.
* **APIs Abertas:** Provedores de MFA, sistemas corporativos e extensões de navegadores.

---

## 11. Visão de Longo Prazo

O objetivo final não é construir apenas um gerenciador de senhas.  
O objetivo é construir uma **plataforma de segurança pessoal** onde o usuário tenha:
1. Controle total sobre seus segredos
2. Visibilidade clara sobre riscos e vulnerabilidades
3. Ferramentas ativas de auditoria
4. Sincronização segura
5. Privacidade por padrão

---

## 12. Próximos Passos Prioritários

### Curto Prazo
1. Manter a suíte de testes e validação de segurança como gate de release.
2. Evoluir a experiência de instalação e demonstração do Alpha.
3. Preparar os próximos incrementos de desktop/extensão sem comprometer o modelo zero-knowledge.

### Médio Prazo
1. Aplicação Desktop (Electron + API Local).
2. Protocolo de comunicação IPC / API Local segura.
3. Extensão de navegador (Chrome / Chromium).

### Longo Prazo
1. Camada de sincronização em nuvem (SaaS Zero-Knowledge).
2. Arquitetura SaaS Multi-Tenant.
3. Compartilhamento seguro entre cofres (chave assimétrica / criptografia de chave pública).
4. Recursos para organizações e equipes.
5. Plataforma completa de gestão e segurança da vida digital.

---

## 13. Evolução da Visão do Produto: Identidade Digital

O VaultLocal expande o escopo tradicional de "Password Manager" para:
> **Organizar, proteger e monitorar toda a identidade digital de uma pessoa.**

O propósito evolui de armazenar credenciais para fornecer visibilidade, segurança e controle sobre todos os ativos digitais e documentais relevantes do indivíduo.

---

## 14. Painel de Vida Digital

O Painel de Vida Digital atua como ponto de entrada principal, provendo scores granulares e orientações acionáveis.

### Exemplo de Métricas Consolidadas:
* **Segurança:** `88/100`
* **Identidade:** `95/100`
* **Financeiro:** `72/100`
* **Infraestrutura:** `65/100`
* **Assinaturas:** `80/100`

### Questões Centrais Respondidas:
* *Minha vida digital está segura?*
* *Existem riscos imediatos que exigem atenção?*
* *O que devo revisar ou rotacionar primeiro?*
* *Existem ativos, cartões ou documentos próximos do vencimento?*

### Painel de Alertas Táticos:
* ⚠️ **4 senhas reutilizadas**
* ⚠️ **3 contas sem MFA**
* ⚠️ **2 documentos vencendo**
* ⚠️ **1 domínio expira em 15 dias**
* ⚠️ **3 assinaturas sem uso recente**

---

## 15. Asset Vault (Cofre de Ativos)

Trata qualquer recurso crítico como um ativo de valor:

```
                      ┌──────────────────────┐
                      │     Asset Vault      │
                      └──────────┬───────────┘
         ┌───────────────┬───────┴───────┬───────────────┐
         ▼               ▼               ▼               ▼
   [Identidade]    [Financeiro]      [Digitais]     [Engenharia / Dev]
   - RG / CNH      - Cartões         - Google       - API Keys
   - Passaporte    - Contas          - GitHub       - SSH Keys
   - CPF           - Seguros         - AWS/Cloud    - Tokens
   - Título        - Financiamentos  - Domínios     - Certificados
                   - Assinaturas                    - Arquivos .env
```

---

## 16. Life Events (Momentos e Jornadas de Vida)

Organização de ativos contextuais orientada a eventos reais da vida:

* **Viagem Internacional:** Checklist de Passaporte, Seguro Viagem, Cartões Internacionais, Reservas, Vistos, Documentos.
* **Troca de Emprego:** Contrato, Holerites, Benefícios, Acessos Corporativos, Atualização de Perfil Profissional.
* **Compra de Veículo:** Documento do Veículo, Seguro, Licenciamento, Financiamento, Chave Reserva.

Transforma o cofre em um orquestrador documental para contingências e marcos do usuário.

---

## 17. Developer Hub

Módulo dedicado a desenvolvedores, DevOps, SRE, ITOps e engenheiros de cloud:

### Ativos Monitorados:
* API Keys, SSH Keys, Tokens de Acesso Pessoal (PAT), Certificados SSL/TLS, Credenciais de Bancos de Dados e Secrets de ambiente.

### Alertas Técnicos:
* ⚠️ *Certificado expira em 20 dias*
* ⚠️ *Token sem uso há 180 dias*
* ⚠️ *Chave com permissões administrativas excessivas*

---

## 18. Sistema de Regras e Saúde Digital (Determinístico)

A avaliação de segurança adota uma matriz de regras transparentes, explicáveis e auditáveis, operando 100% offline sem dependência de serviços externos ou IA:

$$\text{Risco Total} = \sum \text{Penalidades}$$

* **Senha reutilizada:** $+20$ risco
* **Sem MFA:** $+15$ risco
* **Token expirando:** $+10$ risco
* **Documento vencendo:** $+10$ risco

*Vantagens:* Explicável, auditável, determinístico, privado e funcional sem internet. Uma camada opcional de IA poderá ser plugada no futuro, mas o core do produto nunca dependerá dela.

---

## 19. Posicionamento Estratégico

> **Definição de Mercado:**  
> **Plataforma de gestão da identidade digital, segurança pessoal e ativos digitais**, construída com privacidade radical, criptografia Zero-Knowledge e soberania do usuário como pilares inegociáveis.

---

## 20. Fases da Evolução Conceitual

$$\text{v1: Password Manager} \longrightarrow \text{v2: Personal Security Hub} \longrightarrow \text{v3: Digital Identity \& Asset Vault} \longrightarrow \text{v4: Plataforma de Vida Digital}$$

* **VaultLocal v1:** Password Manager Local First
* **VaultLocal v2:** Personal Security Hub com auditoria ativa
* **VaultLocal v3:** Digital Identity & Asset Vault abrangente
* **VaultLocal v4:** Plataforma Completa de Gestão da Vida Digital

---

## 21. Catálogo de Features & Inovações

Para detalhamento conceitual de features complementares (Digital Legacy, Security Timeline, Relationship Graph, Emergency Mode, Personal Runbooks, Secret Expiration Center e Project Vaults), consulte o documento dedicado:
👉 [docs/FEATURE_IDEAS.md](file:///home/matheusaraujosami/Documentos/vaultlocal/docs/FEATURE_IDEAS.md)

