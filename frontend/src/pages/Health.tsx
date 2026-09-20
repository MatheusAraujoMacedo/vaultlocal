import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { analyze } from '../health/engine'
import { computeScore } from '../health/score'
import type { EntryForAnalysis } from '../health/rules'
import { unwrapDataKey, decryptField, getSessionKek } from '../crypto'

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

  useEffect(() => {
    ;(async () => {
      try {
        const list = await api.listEntries()
        const blobs = await Promise.all(list.map((e) => api.getEntry(e.id)))
        const kek = getSessionKek()

        const titleById = new Map<string, string>()
        for (const b of blobs) titleById.set(b.id, b.title)

        const forAnalysis: EntryForAnalysis[] = await Promise.all(
          blobs.map(async (b) => {
            const key = await unwrapDataKey(
              { wrapped_data_key: b.wrapped_data_key, wrapped_nonce: b.wrapped_nonce },
              kek,
            )
            const password = await decryptField(
              { ciphertext: b.password_enc, nonce: b.nonce_password },
              key,
            )
            return { id: b.id, password, updatedAt: b.updated_at }
          }),
        )

        const report = analyze(forAnalysis)
        const newScore = computeScore(report)

        try {
          await api.postHealthReport({
            score: newScore,
            total_entries: report.totalEntries,
            weak_count: report.weakCount,
            reused_count: report.reusedCount,
            old_count: report.oldCount,
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

        const flat: IssueView[] = []
        for (const eh of report.entries) {
          for (const iss of eh.issues) {
            flat.push({
              entryId: eh.entryId,
              entryTitle: titleById.get(eh.entryId) ?? eh.entryId,
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

      <section className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-8">
        <div className="border border-stone-200 rounded-lg bg-white p-4">
          <p className="text-sm text-stone-500">Senhas fracas</p>
          <p className="mt-1 text-2xl font-semibold text-stone-900 tabular-nums">
            {counts.weak}
          </p>
        </div>
        <div className="border border-stone-200 rounded-lg bg-white p-4">
          <p className="text-sm text-stone-500">Senhas reutilizadas</p>
          <p className="mt-1 text-2xl font-semibold text-stone-900 tabular-nums">
            {counts.reused}
          </p>
        </div>
        <div className="border border-stone-200 rounded-lg bg-white p-4">
          <p className="text-sm text-stone-500">Senhas antigas</p>
          <p className="mt-1 text-2xl font-semibold text-stone-900 tabular-nums">
            {counts.old}
          </p>
        </div>
      </section>

      {issues.length === 0 ? (
        <div className="border border-stone-200 rounded-lg bg-white p-8 text-center">
          <p className="text-sm text-stone-500">
            Nenhum problema encontrado. Continue com bons hábitos.
          </p>
        </div>
      ) : (
        <section className="border border-stone-200 rounded-lg bg-white divide-y divide-stone-200">
          {issues.map((iss, i) => (
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
