import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, VaultSession } from '../api'

function formatDate(value: string): string {
  return new Date(value).toLocaleString('pt-BR', {
    dateStyle: 'short',
    timeStyle: 'short',
  })
}

export default function Sessions() {
  const [sessions, setSessions] = useState<VaultSession[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')
  const nav = useNavigate()

  async function load() {
    setLoading(true)
    setError('')
    try {
      const result = await api.listSessions()
      setSessions(result.sessions)
    } catch (err: any) {
      if (err.message?.includes('401') || err.message === 'invalid session') {
        api.logout()
        nav('/login')
        return
      }
      setError(err.message || 'Não foi possível carregar as sessões')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [])

  async function revoke(session: VaultSession) {
    const label = session.current ? 'esta sessão' : 'esta sessão remota'
    if (!window.confirm(`Revogar ${label}? O acesso dessa sessão será encerrado.`)) return
    setBusy(session.id)
    setError('')
    try {
      await api.revokeSession(session.id)
      if (session.current) {
        api.logout()
        nav('/login')
        return
      }
      setSessions((current) => current.filter((item) => item.id !== session.id))
    } catch (err: any) {
      setError(err.message || 'Não foi possível revogar a sessão')
    } finally {
      setBusy(null)
    }
  }
  async function revokeOthers() {
    const remoteCount = sessions.filter((session) => !session.current).length
    if (remoteCount === 0) return
    if (!window.confirm(`Revogar as ${remoteCount} outras sessões?`)) return
    setBusy('others')
    setError('')
    try {
      await api.revokeOtherSessions()
      setSessions((current) => current.filter((session) => session.current))
    } catch (err: any) {
      setError(err.message || 'Não foi possível revogar as outras sessões')
    } finally {
      setBusy(null)
    }
  }

  const remoteCount = sessions.filter((session) => !session.current).length

  return (
    <div className="min-h-screen bg-stone-50">
      <header className="border-b border-stone-200 bg-white">
        <div className="max-w-3xl mx-auto px-4 py-4 flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-wide text-stone-400">VaultLocal</p>
            <h1 className="text-lg font-semibold text-stone-900">Sessões ativas</h1>
          </div>
          <Link to="/" className="text-sm text-stone-500 hover:text-stone-900">← Cofre</Link>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-4 py-8">
        <div className="mb-5 rounded-lg border border-stone-200 bg-white p-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div>
              <p className="text-sm font-medium text-stone-900">Controle de sessões</p>
              <p className="text-xs text-stone-500 mt-1">
                Revogue acessos antigos sem alterar as credenciais ou o conteúdo cifrado do cofre.
              </p>
            </div>
            <button
              type="button"
              onClick={revokeOthers}
              disabled={remoteCount === 0 || busy !== null}
              className="px-3 py-2 rounded-md border border-stone-300 text-sm text-stone-700 hover:bg-stone-50 disabled:opacity-50"
            >
              {busy === 'others' ? 'Revogando…' : 'Revogar outras sessões'}
            </button>
          </div>
        </div>

        {error && (
          <p className="mb-4 text-sm text-red-700 bg-red-50 border border-red-200 rounded-md px-3 py-2">
            {error}
          </p>
        )}

        {loading ? (
          <p className="text-sm text-stone-500">Carregando sessões…</p>
        ) : sessions.length === 0 ? (
          <p className="text-sm text-stone-500">Nenhuma sessão ativa encontrada.</p>
        ) : (
          <div className="space-y-3">
            {sessions.map((session) => (
              <div
                key={session.id}
                className="rounded-lg border border-stone-200 bg-white px-4 py-4"
              >
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-stone-900">
                        {session.current ? 'Sessão atual' : 'Sessão ativa'}
                      </p>
                      {session.current && (
                        <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                          Atual
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-stone-500 mt-1">
                      Criada em {formatDate(session.created_at)}
                    </p>
                    <p className="text-xs text-stone-400 mt-0.5">
                      Expira em {formatDate(session.expires_at)}
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => revoke(session)}
                    disabled={busy !== null}
                    className="self-start sm:self-auto px-3 py-1.5 rounded-md border border-red-200 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                  >
                    {busy === session.id ? 'Revogando…' : 'Revogar'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}

        <p className="mt-6 text-xs text-stone-400">
          O VaultLocal identifica sessões por criação e validade. Informações de conteúdo do cofre não são expostas nesta tela.
        </p>
      </main>
    </div>
  )
}
