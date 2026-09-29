# Health Dashboard

Painel que analisa as senhas do cofre e apresenta um score de saúde (0-100)
com a lista de problemas encontrados. Toda a análise roda no navegador, sobre
senhas já descriptografadas pela sessão local; o servidor recebe apenas os
contadores agregados.

## 1. Objetivo

Dar ao usuário visibilidade sobre a higiene das suas senhas (fracas,
reutilizadas, antigas) e um caminho direto de correção ("Trocar agora" leva ao
formulário de edição da entrada).

## 2. Arquitetura

```
┌──────────────────────────┐
│ Frontend (/health page)  │
│  1. GET /entries         │
│  2. GET /entries/{id}    │  (blobs cifrados)
│  3. unwrap + decrypt     │  (KEK em memória, zero-knowledge)
│  4. health/engine.analyze│
│  5. health/score.compute │
│  6. POST /health/report  │  (best-effort, contagens agregadas)
└────────────┬─────────────┘
             ▼
┌──────────────────────────┐
│ Backend                  │
│  POST /api/v1/health/report   (upsert, 1 relatório por usuário)
│  GET  /api/v1/health/latest   (último relatório ou 404)
└────────────┬─────────────┘
             ▼
     tabela health_reports
```

Decisão-chave: o backend é zero-knowledge e nunca vê senhas em claro, então a
regras de análise vivem no frontend (`frontend/src/health/`). O servidor só
persiste contagens — nunca o score, nunca issues, nunca conteúdo de entrada.

## 3. Modelo de dados

### Backend (PostgreSQL, migração `002_add_health_reports`)

```sql
health_reports (
  id            UUID PK,
  user_id       UUID UNIQUE REFERENCES users(id) ON DELETE CASCADE,  -- 1 relatório/usuário
  total_entries INT NOT NULL,
  weak_count    INT NOT NULL,
  reused_count  INT NOT NULL,
  old_count     INT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL,
  updated_at    TIMESTAMPTZ NOT NULL,
  CHECK (total_entries >= 0),
  CHECK (weak_count   >= 0 AND weak_count   <= total_entries),
  CHECK (reused_count >= 0 AND reused_count <= total_entries),
  CHECK (old_count    >= 0 AND old_count    <= total_entries)
)
```

Sem coluna `score`: o score é derivado das contagens pela fórmula determinística
(seção 6) e recalculado no cliente quando necessário. Sem histórico: o POST faz
upsert na linha única do usuário.

### Frontend

```ts
// health/engine.ts
interface HealthReport {
  totalEntries: number
  weakCount: number       // entradas com ao menos 1 issue da WeakRule
  reusedCount: number     // entradas cuja senha aparece em 2+ entradas
  oldCount: number        // entradas com > 365 dias sem atualizar
  breachedCount: number   // entradas encontradas no último breach check
  entries: EntryHealth[]  // issues detalhadas por entrada
}
```

## 4. API

Base: `/api/v1`. Ambas exigem `Authorization: Bearer <access_token>`.

| Método | Rota              | Body / Resposta                                              |
|--------|-------------------|--------------------------------------------------------------|
| POST   | `/health/report`  | Body: `{score, total_entries, weak_count, reused_count, old_count, breached_count}`. Upsert por `user_id`. Retorna o relatório agregado. |
| GET    | `/health/latest`  | Retorna o relatório persistido (`{id, user_id, score, total_entries, weak_count, reused_count, old_count, breached_count, created_at}`) ou `404` se nunca houve análise. |

Observações:
- O POST é fire-and-forget no cliente (falha não bloqueia a UI).
- `score` continua no payload por compatibilidade, mas o valor persistido não é usado
  para cálculo. O servidor deriva o score das contagens, incluindo `breached_count`.
- `breached_count` é somente uma contagem agregada de entradas afetadas; detalhes por
  entrada ficam no navegador e nunca são persistidos no backend.

## 5. Rules engine

Módulo: `frontend/src/health/`.

```
EntryForAnalysis { id, password, updatedAt }
           │
           ▼  (cada regra produz EntryIssue[] com entryId)
  ┌──────────────────────────────────────────────┐
  │ WeakRule   → severity critical, 1 issue/entry│
  │ ReuseRule  → severity warning, 1 issue/entry │
  │ OldRule    → severity info,    1 issue/entry │
  │ BreachCheck→ severity critical, 1 issue/entry│
  └──────────────────────────────────────────────┘
           │
           ▼  agregação por entryId
  EntryHealth { hasWeak, hasReuse, hasOld, issues[] }
           │
           ▼  contagens: weakCount = #entries com hasWeak, etc.
  BreachCheck → matches detalhados só no cliente
           │
           ▼
  HealthReport { ... , breachedCount }
```

### Regra 1 — `WeakRule` (critical)

Marca a entrada se qualquer uma das condições for verdadeira:
- comprimento < 12
- presente em `COMMON_PASSWORDS` (lista curada de ~35 senhas)
- somente letras (`^[a-zA-Z]+$`)
- somente dígitos (`^[0-9]+$`)

```
for entry in entries:
    reasons = []
    if len(pwd) < 12:            reasons += "senha curta"
    if pwd.lower() in COMMON:    reasons += "senha comum"
    if is_alpha_only(pwd):       reasons += "somente letras"
    if is_digits_only(pwd):      reasons += "somente digitos"
    if reasons: emit(critical, "Senha fraca: " + join(reasons))
```

### Regra 2 — `ReuseRule` (warning)

Agrupa por senha exata; todo grupo com 2+ entradas emite issue em cada membro.

```
groups = group_by(entries, password)
for group in groups where size >= 2:
    for entry in group:
        emit(warning, "Senha reutilizada em N entradas")
```

### Regra 3 — `OldRule` (info, informativa)

```
for entry in entries:
    if now - parse(entry.updatedAt) > 365 days:
        emit(info, "Senha com mais de 365 dias desde a ultima atualizacao")
```

Separador das contagens: uma entrada pode acionar várias regras; cada contador
incrementa no máximo 1 por entrada (via flags `hasWeak`/`hasReuse`/`hasOld`).

## 6. Fórmula do score

```
score = clamp(
  100
  - 20 * breachedCount
  - 15 * weakCount
  - 10 * reusedCount,
  0,
  100
)
```

- Cofre vazio → 100.
- `oldCount` não penaliza (OldRule é informativa).
- Rótulos na UI: >=90 Excelente, >=75 Bom, >=50 Atenção, <50 Crítico.
- Delta de score vs. análise anterior é mantido em `localStorage`
  (`vaultlocal:health:last`), não no servidor.

## 7. Decisões de MVP (cortes conscientes)

- **HIBP** — a primeira implementação é opt-in e client-side usando a API pública
  de Pwned Passwords com k-anonymity. Apenas os 5 primeiros caracteres do SHA-1
  são enviados; o restante é comparado localmente. O corpus HIBP completo não é
  embarcado no aplicativo.
- **Modo offline completo** — separado da primeira implementação para evitar
  distribuir um corpus de múltiplos GB no bundle. Será uma etapa posterior com
  índice local/importável.
- **Histórico de relatórios** — cortado. Um único relatório por usuário
  (upsert). Tendência aproximada fica no `localStorage` do navegador (delta de
  score). Evita crescimento de tabela e decisões de retenção.
- **Score persistido no banco** — cortado. Como é função pura das contagens,
  recalcular no cliente é mais simples e evita drift entre coluna e fórmula.
- **Componente `StatCard` dedicado** — cortado. Os três cartões de contagem são
  markup inline na página; prematuro abstrair para 3 usos.

## 8. Limitações conhecidas

- O delta "desde a última análise" é por navegador (localStorage), não segue o
  usuário entre máquinas.
- `ReuseRule` compara senhas byte a byte; não detecta variações triviais
  (`senha1` vs `senha2`).
- Persistência do relatório é best-effort: se o POST falhar, a UI ainda mostra
  o resultado, mas `/health/latest` fica defasado.
- Análise exige KEK em sessão; reload da página força novo login antes de abrir
  `/health`.
- Lista `COMMON_PASSWORDS` é pequena (~35 entradas) e estática.

## 9. Modo offline local

A Phase 5.2 usa o downloader oficial do HIBP no formato de diretório. O downloader
gera os ranges SHA-1 individualmente e mantém `sha1.index` com os ETags para
permitir atualizações incrementais sem baixar novamente ranges inalterados.

O VaultLocal espera o corpus em:

```
data/hibp/sha1/
├── sha1.index
├── 00000.txt
├── 00001.txt
└── ...
```

Somente esse diretório é montado na API como read-only. O navegador envia ao
backend local apenas o prefixo SHA-1 de 5 caracteres, recebe o range correspondente
e faz o match do suffix localmente.

Para instalar/atualizar o corpus:

```bash
dotnet tool install --global haveibeenpwned-downloader
make hibp-download
make hibp-index-ready
```

É possível ajustar o paralelismo, por exemplo:

```bash
make hibp-download P=32
```

O corpus não deve ser commitado no repositório.

## 10. Próximos passos

- Regra de entropia (zxcvbn ou equivalente) em vez de heurísticas de regex.
- Detecção de reutilização por similaridade (hash normalizado, edição).
- Histórico de relatórios com janela fixa (ex.: últimos 30) quando houver
  necessidade real de tendência server-side.
- Botão "corrigir tudo" sugerindo senhas geradas em lote para entradas fracas.
- Cobertura de testes de UI para `/health` (hoje só unit tests do engine/score).

## 11. Roteiro E2E manual

Pré-condição: stack no ar (`docker compose up -d --build`) e um usuário criado.

1. Login em `http://localhost:8080` com usuário que tenha entradas.
2. Criar/editar entradas cobrindo os casos:
   - uma senha fraca (ex.: `abc123`),
   - duas entradas com a mesma senha,
   - uma entrada com `updated_at` > 365 dias (editar direto no banco:
     `UPDATE vault_entries SET updated_at = now() - interval '400 days' WHERE title='...'`).
3. Navegar para `/health` (link "Saúde" no topo do cofre).
4. Verificar:
   - Header mostra score 0-100 e rótulo correto.
   - 3 cartões com contagens batem com o cenário montado.
   - Lista de issues mostra cada entrada com severidade e mensagem esperadas.
   - Botão "Trocar agora" abre `/entry/:id/edit?issue=<ruleId>`.
5. Trocar a senha fraca por uma forte, voltar a `/health`, confirmar:
   - score subiu e o delta "+N pontos desde a última análise" aparece,
   - contador de fracas zerou.
6. Conferir persistência (best-effort):
   - `docker compose exec db psql -U vault vaultdb -c 'SELECT * FROM health_reports;'`
   - deve haver exatamente 1 linha por usuário, atualizada a cada visita.
7. Clicar em "Verificar agora" em um navegador com internet e confirmar que a
   entrada comprometida aparece como issue crítica sem que senha ou hash completo
   apareçam na requisição.
8. Cofre vazio: novo usuário sem entradas → score 100, sem issues,
   mensagem "Nenhum problema encontrado".
9. Reload da página `/health`: os detalhes por entrada do breach check não devem
   sobreviver ao reload; o backend pode manter apenas o `breached_count` agregado.
10. Reload da página `/health` com KEK expirada: fazer login novamente e repetir a análise.

## 12. Testes automatizados

- Backend: `make test-backend` (pytest; cobre os endpoints de health quando
  presentes, além do CRUD e auth).
- Frontend: `make test-frontend` (vitest; `health/score.test.ts` e
  `health/rules.test.ts`).
