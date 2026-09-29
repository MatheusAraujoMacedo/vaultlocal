import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, getAccessToken } from '../api'
import { analyze } from '../health/engine'
import { checkPasswordsWithHibp, checkPasswordsWithLocalIndex, type BreachSource } from '../health/breach'
import { computeScore } from '../health/score'
import type { EntryForAnalysis } from '../health/rules'
import { unwrapDataKey, decryptField, getSessionKek, buildDataKeyAad, buildFieldAad } from '../crypto'

const LS_KEY = 'vaultlocal:health:last'

type Severity = 'critical' | 'warning' | 'info'

interface IssueView {
  entryId: string
  entryTitle: string
  ruleId: string
  severity: Severity
  message: string
}

function labelFor(score: number): string {
  if (score >= 90) return 'Excelente'
  if (score >= 75) return 'Bom'
  if (score >= 50) return 'Atenção'
  return 'Crítico'
}

function severityClass(s: Severity): string {
  if (s === 'critical') return 'text-red-700'
  if (s === 'warning') return 'text-amber-700'
  return 'text-stone-500'
}

export default function Health() {
  const nav = useNavigate()
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [score, setScore] = useState(0)
  const [delta, setDelta] = useState<number | null>(null)
  const [counts, setCounts] = useState({ weak: 0, reused: 0, old: 0 })
  const [issues, setIssues] = useState<IssueView[]>([])
  const [analysisEntries, setAnalysisEntries] = useState<EntryForAnalysis[]>([])
  const [entryTitles, setEntryTitles] = useState<Record<string, string>>({})
  const [breachMatches, setBreachMatches] = useState<IssueView[]>([])
  const [breachedCount, setBreachedCount] = useState(0)
  const [breachLoading, setBreachLoading] = useState(false)
  const [breachStatus, setBreachStatus] = useState<'idle' | 'success' | 'error'>('idle')
  const [breachError, setBreachError] = useState('')
  const [localIndexAvailable, setLocalIndexAvailable] = useState(false)
  const [breachSource, setBreachSource] = useState<BreachSource>('online')
  const [filterRule, setFilterRule] = useState<string | null>(null)

  useEffect(() => {
    ;(async () => {
      try {
        const list = await api.listEntries()
        const blobs = await Promise.all(list.map((e) => api.getEntry(e.id)))
        const kek = getSessionKek()

        const titleById: Record<string, string> = {}
        for (const b of blobs) titleById[b.id] = b.title
        setEntryTitles(titleById)

        const forAnalysis: EntryForAnalysis[] = await Promise.all(
          blobs.map(async (b) => {
            const dataKeyAad = b.crypto_version === 2 ? buildDataKeyAad(b.id) : undefined
            const key = await unwrapDataKey(
              { wrapped_data_key: b.wrapped_data_key, wrapped_nonce: b.wrapped_nonce },
              kek,
              dataKeyAad,
            )
            const password = await decryptField(
              { ciphertext: b.password_enc, nonce: b.nonce_password },
              key,
              b.crypto_version === 2 ? buildFieldAad(b.id, b.title, b.site, 'password') : undefined,
            )
            return { id: b.id, password, updatedAt: b.updated_at }
          }),
        )

        const report = analyze(forAnalysis)
        const latest = await api.getLatestHealth().catch(() => null)
        const lastBreachedCount = latest?.breached_count ?? 0
        const scoreReport = { ...report, breachedCount: lastBreachedCount }
        const newScore = computeScore(scoreReport)

        try {
          await api.postHealthReport({
            score: newScore,
            total_entries: report.totalEntries,
            weak_count: report.weakCount,
            reused_count: report.reusedCount,
            old_count: report.oldCount,
            breached_count: lastBreachedCount,
          })
        } catch {
          /* report persistence is best-effort */
        }

        const lastRaw = localStorage.getItem(LS_KEY)
        if (lastRaw) {
          try {
            const prev = JSON.parse(lastRaw) as { score: number }
            setDelta(newScore - prev.score)
          } catch {
            /* corrupted */
          }
        }
        localStorage.setItem(LS_KEY, JSON.stringify({ score: newScore, at: new Date().toISOString() }))

        setScore(newScore)
        setCounts({ weak: report.weakCount, reused: report.reusedCount, old: report.oldCount })
        setBreachedCount(lastBreachedCount)
        setAnalysisEntries(forAnalysis)

        const localStatus = await api
          .getLocalBreachStatus()
          .catch(() => ({ available: false, source: 'hibp-local-sha1' }))
        setLocalIndexAvailable(localStatus.available)
        setBreachSource(localStatus.available ? 'local' : 'online')

        const flat: IssueView[] = []
        for (const eh of report.entries) {
          for (const iss of eh.issues) {
            flat.push({
              entryId: eh.entryId,
              entryTitle: titleById[eh.entryId] ?? eh.entryId,
              ruleId: iss.ruleId,
              severity: iss.severity,
              message: iss.message,
            })
          }
        }
        setIssues(flat)
      } catch (e: any) {
        const msg = e?.message ?? 'Erro ao calcular saúde do cofre'
        if (msg.includes('401') || msg.toLowerCase().includes('unauthorized')) {
          api.logout()
          nav('/login')
          return
        }
        setError(msg)
      } finally {
        setLoading(false)
      }
    })()
  }, [nav])

  async function runBreachCheck() {
    setBreachLoading(true)
    setBreachStatus('idle')
    setBreachError('')

    try {
      const result =
        breachSource === 'local'
          ? await checkPasswordsWithLocalIndex(
              analysisEntries.map((entry) => ({ id: entry.id, password: entry.password })),
              getAccessToken() ?? '',
            )
          : await checkPasswordsWithHibp(
              analysisEntries.map((entry) => ({ id: entry.id, password: entry.password })),
            )

      const nextBreachMatches: IssueView[] = result.matches.map((match) => ({
        entryId: match.entryId,
        entryTitle: entryTitles[match.entryId] ?? match.entryId,
        ruleId: 'breached-password',
        severity: 'critical',
        message:
          match.prevalence === 1
            ? 'Senha encontrada em vazamento conhecido (1 ocorrência)'
            : 'Senha encontrada em vazamentos conhecidos (' + match.prevalence + ' ocorrências)',
      }))

      const nextBreachedCount = result.matches.length
      const report = analyze(analysisEntries)
      const score = computeScore({ ...report, breachedCount: nextBreachedCount })

      const lastRaw = localStorage.getItem(LS_KEY)
      if (lastRaw) {
        try {
          const prev = JSON.parse(lastRaw) as { score: number }
          setDelta(score - prev.score)
        } catch {
          /* corrupted */
        }
      }
      localStorage.setItem(LS_KEY, JSON.stringify({ score, at: new Date().toISOString() }))

      setBreachMatches(nextBreachMatches)
      setBreachedCount(nextBreachedCount)
      setScore(score)
      setBreachStatus('success')

      try {
        await api.postHealthReport({
          score,
          total_entries: report.totalEntries,
          weak_count: report.weakCount,
          reused_count: report.reusedCount,
          old_count: report.oldCount,
          breached_count: nextBreachedCount,
        })
      } catch {
        /* report persistence is best-effort */
      }
    } catch (e: any) {
      setBreachStatus('error')
      if (e?.name === 'AbortError') {
        setBreachError('A consulta ao HIBP expirou. Nenhum dado do cofre foi enviado ao servidor VaultLocal.')
      } else {
        setBreachError(e?.message ?? 'Não foi possível concluir a verificação de vazamentos')
      }
    } finally {
      setBreachLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-12">
        <p className="text-sm text-stone-500">Analisando senhas…</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-3xl mx-auto px-4 py-12">
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
          {error}
        </p>
        <Link to="/" className="block mt-4 text-sm text-stone-900 hover:underline">
          ← Voltar
        </Link>
      </div>
    )
  }

  const label = labelFor(score)

  return (
    <div className="max-w-3xl mx-auto px-4 py-8">
      <Link to="/" className="text-sm text-stone-500 hover:text-stone-900 transition">
        ← Voltar
      </Link>

      <header className="mt-4 mb-8 border border-stone-200 rounded-lg bg-white p-6">
        <div className="flex items-end justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-sm font-medium text-stone-500 uppercase tracking-wide">
              Saúde do cofre
            </h1>
            <div className="mt-2 flex items-baseline gap-3">
              <span className="text-6xl font-semibold text-stone-900 tabular-nums">
                {score}
              </span>
              <span className="text-lg text-stone-500">/ 100</span>
            </div>
            <p className="mt-2 text-sm font-medium text-stone-900">{label}</p>
          </div>
          {delta !== null && (
            <div className="text-sm text-stone-500">
              {delta === 0
                ? 'Sem mudança desde a última análise'
                : delta > 0
                  ? `+${delta} pontos desde a última análise`
                  : `${delta} pontos desde a última análise`}
            </div>
          )}
        </div>
      </header>

      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-8">
        <button
          type="button"
          onClick={() => setFilterRule(filterRule === 'weak-password' ? null : 'weak-password')}
          className={`border rounded-lg p-4 text-left transition ${
            filterRule === 'weak-password'
              ? 'border-stone-900 bg-stone-50 ring-2 ring-stone-900'
              : 'border-stone-200 bg-white hover:border-stone-300'
          }`}
        >
          <p className="text-sm text-stone-500">Senhas fracas</p>
          <p className="mt-1 text-2xl font-semibold text-stone-900 tabular-nums">
            {counts.weak}
          </p>
        </button>
        <button
          type="button"
          onClick={() => setFilterRule(filterRule === 'reused-password' ? null : 'reused-password')}
          className={`border rounded-lg p-4 text-left transition ${
            filterRule === 'reused-password'
              ? 'border-stone-900 bg-stone-50 ring-2 ring-stone-900'
              : 'border-stone-200 bg-white hover:border-stone-300'
          }`}
        >
          <p className="text-sm text-stone-500">Senhas reutilizadas</p>
          <p className="mt-1 text-2xl font-semibold text-stone-900 tabular-nums">
            {counts.reused}
          </p>
        </button>
        <button
          type="button"
          onClick={() => setFilterRule(filterRule === 'old-password' ? null : 'old-password')}
          className={`border rounded-lg p-4 text-left transition ${
            filterRule === 'old-password'
              ? 'border-stone-900 bg-stone-50 ring-2 ring-stone-900'
              : 'border-stone-200 bg-white hover:border-stone-300'
          }`}
        >
          <p className="text-sm text-stone-500">Senhas antigas</p>
          <p className="mt-1 text-2xl font-semibold text-stone-900 tabular-nums">
            {counts.old}
          </p>
        </button>
        <button
          type="button"
          onClick={() => setFilterRule(filterRule === 'breached-password' ? null : 'breached-password')}
          className="border border-stone-200 bg-white hover:border-stone-300 rounded-lg p-4 text-left transition"
        >
          <p className="text-sm text-stone-500">Em vazamentos</p>
          <p className="mt-1 text-2xl font-semibold text-stone-900 tabular-nums">
            {breachedCount}
          </p>
        </button>
      </section>

      <section className="mb-8 border border-stone-200 rounded-lg bg-white p-5">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h2 className="text-sm font-medium text-stone-900">Verificar vazamentos conhecidos</h2>
            <p className="mt-1 text-sm text-stone-500 max-w-2xl">
              A senha é hasheada no navegador e apenas a faixa necessária é consultada. No modo
              local, nenhuma consulta deixa a máquina; no modo online, apenas o prefixo de 5
              caracteres é enviado ao HIBP e o match completo fica no navegador.
            </p>
            {breachedCount > 0 && breachStatus === 'idle' && (
              <p className="mt-2 text-xs text-stone-500">
                Última verificação registrada: {breachedCount} entrada(s) encontrada(s).
              </p>
            )}
            {breachStatus === 'success' && (
              <p className="mt-2 text-xs text-stone-600">
                Verificação concluída: {breachedCount} entrada(s) encontrada(s) em bases de vazamento.
              </p>
            )}
            {breachError && <p className="mt-2 text-xs text-red-600">{breachError}</p>}
            <p className="mt-2 text-xs text-stone-400">
              Fonte: {breachSource === 'local' ? 'índice local HIBP' : 'HIBP online (k-anonymity)'}
              {!localIndexAvailable && ' · índice local não instalado'}
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {localIndexAvailable && (
              <select
                value={breachSource}
                onChange={(e) => setBreachSource(e.target.value as BreachSource)}
                disabled={breachLoading}
                className="px-2.5 py-2 rounded-md border border-stone-300 bg-white text-sm text-stone-700"
              >
                <option value="local">Índice local</option>
                <option value="online">HIBP online</option>
              </select>
            )}
            <button
            type="button"
            onClick={runBreachCheck}
            disabled={breachLoading || analysisEntries.length === 0}
            className="shrink-0 px-3 py-2 rounded-md border border-stone-300 text-sm text-stone-700 hover:bg-stone-50 disabled:opacity-50 disabled:cursor-not-allowed transition"
          >
              {breachLoading ? 'Verificando…' : 'Verificar agora'}
            </button>
          </div>
        </div>
      </section>

      {filterRule && (
        <div className="flex items-center justify-between mb-4 px-1">
          <span className="text-xs text-stone-500">
            Filtrando por:{' '}
            <strong className="text-stone-900">
              {filterRule === 'weak-password'
                ? 'Senhas fracas'
                : filterRule === 'reused-password'
                  ? 'Senhas reutilizadas'
                  : filterRule === 'old-password'
                    ? 'Senhas antigas'
                    : 'Senhas em vazamentos'}
            </strong>
          </span>
          <button
            type="button"
            onClick={() => setFilterRule(null)}
            className="text-xs text-stone-600 hover:text-stone-900 underline"
          >
            Limpar filtro
          </button>
        </div>
      )}

      {issues.length === 0 && breachMatches.length === 0 ? (
        <div className="border border-stone-200 rounded-lg bg-white p-8 text-center">
          <p className="text-sm text-stone-500">
            Nenhum problema encontrado. Continue com bons hábitos.
          </p>
        </div>
      ) : (
        <section className="border border-stone-200 rounded-lg bg-white divide-y divide-stone-200">
          {[...issues, ...breachMatches]
            .filter((iss) => (filterRule ? iss.ruleId === filterRule : true))
            .map((iss, i) => (
              <div key={`${iss.entryId}-${iss.ruleId}-${i}`} className="p-4 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-stone-900 truncate">
                    {iss.entryTitle}
                  </p>
                  <p className={`mt-0.5 text-sm ${severityClass(iss.severity)}`}>
                    {iss.message}
                  </p>
                </div>
                <Link
                  to={`/entry/${iss.entryId}/edit?issue=${encodeURIComponent(iss.ruleId)}`}
                  className="shrink-0 px-3 py-1.5 rounded-md border border-stone-300 text-sm text-stone-700 hover:bg-stone-50 transition"
                >
                  Trocar agora
                </Link>
              </div>
            ))}
        </section>
      )}
    </div>
  )
}
