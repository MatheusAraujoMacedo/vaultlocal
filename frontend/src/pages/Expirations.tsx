import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, EntryListItem } from '../api'
import { expirationDays, getExpirationState, sortExpirations } from '../security/expiration'

const stateLabels = {
  expired: 'Expiradas',
  urgent: 'Próximos 7 dias',
  soon: 'Próximos 15 dias',
  scheduled: 'Agendadas',
} as const

function formatExpiration(value: string): string {
  return new Date(value).toLocaleString('pt-BR', {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

function relativeLabel(value: string): string {
  const days = expirationDays(value)
  if (days === null) return 'Data inválida'
  if (days < 0) return 'Expirada há ' + Math.abs(days) + 'd'
  if (days === 0) return 'Expira hoje'
  if (days === 1) return 'Expira amanhã'
  return 'Expira em ' + days + 'd'
}

export default function Expirations() {
  const [entries, setEntries] = useState<EntryListItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const nav = useNavigate()

  useEffect(() => {
    ;(async () => {
      try {
        setEntries(await api.listEntries())
      } catch (err: any) {
        if (err.message?.includes('401') || err.message === 'invalid token') {
          api.logout()
          nav('/login')
          return
        }
        setError(err.message || 'Não foi possível carregar as expirações')
      } finally {
        setLoading(false)
      }
    })()
  }, [nav])

  const expirations = useMemo(() => sortExpirations(
    entries
      .filter((entry) => entry.expires_at)
      .map((entry) => ({
        id: entry.id,
        title: entry.title,
        site: entry.site,
        expires_at: entry.expires_at!,
      })),
  ), [entries])

  const counts = useMemo(() => {
    const result = { expired: 0, urgent: 0, soon: 0, scheduled: 0 }
    expirations.forEach((item) => {
      const state = getExpirationState(item.expires_at)
      if (state) result[state] += 1
    })
    return result
  }, [expirations])

  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-200 bg-white/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="text-lg font-semibold tracking-tight text-stone-900">
            Vault<span className="text-stone-400">Local</span>
          </Link>
          <Link to="/" className="text-sm text-stone-500 hover:text-stone-900">← Cofre</Link>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-8">
        <div className="mb-6">
          <p className="text-xs uppercase tracking-wide text-stone-400 font-medium">Developer Hub</p>
          <h1 className="text-2xl font-semibold text-stone-900 mt-1">Central de vencimento</h1>
          <p className="text-sm text-stone-500 mt-2">
            Acompanhe credenciais e outros segredos que precisam ser renovados.
          </p>
        </div>

        {error && (
          <p className="mb-4 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">{error}</p>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
          {(Object.keys(stateLabels) as Array<keyof typeof stateLabels>).map((state) => (
            <div key={state} className="rounded-lg border border-stone-200 bg-white px-4 py-3">
              <p className="text-xs text-stone-400">{stateLabels[state]}</p>
              <p className="text-2xl font-semibold text-stone-900 mt-1">{counts[state]}</p>
            </div>
          ))}
        </div>

        {loading ? (
          <p className="text-sm text-stone-500 text-center py-12">Carregando…</p>
        ) : expirations.length === 0 ? (
          <div className="text-center py-16 border border-dashed border-stone-300 rounded-lg">
            <p className="text-stone-500 text-sm">Nenhuma entrada com data de expiração.</p>
            <Link to="/entry/new" className="inline-block mt-3 text-sm font-medium text-stone-900 hover:underline">
              Adicionar uma expiração →
            </Link>
          </div>
        ) : (
          <div className="border border-stone-200 rounded-lg bg-white overflow-hidden divide-y divide-stone-200">
            {expirations.map((item) => {
              const state = getExpirationState(item.expires_at)
              const days = expirationDays(item.expires_at)
              const urgent = state === 'expired' || state === 'urgent'
              return (
                <Link key={item.id} to={`/entry/${item.id}`} className="block px-4 py-4 hover:bg-stone-50 transition">
                  <div className="flex items-start justify-between gap-4">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-stone-900 truncate">{item.title}</p>
                      {item.site && <p className="text-xs text-stone-500 mt-0.5 truncate">{item.site}</p>}
                      <p className="text-xs text-stone-400 mt-1">{formatExpiration(item.expires_at)}</p>
                    </div>
                    <div className="shrink-0 text-right">
                      <p className={`text-sm font-medium ${urgent ? 'text-red-700' : state === 'soon' ? 'text-amber-700' : 'text-stone-600'}`}>
                        {relativeLabel(item.expires_at)}
                      </p>
                      <p className="text-[11px] text-stone-400 mt-1">{days !== null ? stateLabels[state!] : 'Verificar data'}</p>
                    </div>
                  </div>
                </Link>
              )
            })}
          </div>
        )}
      </main>
    </div>
  )
}
