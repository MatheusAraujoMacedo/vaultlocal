import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, TrashEntry } from '../api'

const RETENTION_DAYS = 30

function remainingLabel(purgeAt: string): string {
  const ms = new Date(purgeAt).getTime() - Date.now()
  const days = Math.max(0, Math.ceil(ms / (24 * 60 * 60 * 1000)))
  return days === 1 ? 'expira em 1 dia' : `expira em ${days} dias`
}

export default function Trash() {
  const [entries, setEntries] = useState<TrashEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [action, setAction] = useState<string | null>(null)
  const [error, setError] = useState('')
  const nav = useNavigate()

  async function load() {
    setLoading(true)
    setError('')
    try {
      setEntries(await api.listTrash())
    } catch (err: any) {
      if (err.message?.includes('401') || err.message === 'invalid token') {
        api.logout()
        nav('/login')
        return
      }
      setError(err.message || 'Não foi possível carregar a lixeira')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
  }, [])

  async function restore(id: string) {
    setAction(id)
    setError('')
    try {
      await api.restoreEntry(id)
      setEntries((current) => current.filter((entry) => entry.id !== id))
    } catch (err: any) {
      setError(err.message || 'Não foi possível restaurar a entrada')
    } finally {
      setAction(null)
    }
  }

  async function permanentlyDelete(id: string) {
    if (!window.confirm('Excluir esta entrada permanentemente? Esta ação não pode ser desfeita.')) return
    setAction(id)
    setError('')
    try {
      await api.permanentlyDeleteEntry(id)
      setEntries((current) => current.filter((entry) => entry.id !== id))
    } catch (err: any) {
      setError(err.message || 'Não foi possível excluir a entrada')
    } finally {
      setAction(null)
    }
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-200 bg-white/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="text-lg font-semibold tracking-tight text-stone-900">
            Vault<span className="text-stone-400">Local</span>
          </Link>
          <Link to="/" className="text-sm text-stone-500 hover:text-stone-900 transition">
            ← Voltar ao cofre
          </Link>
        </div>
      </header>
      <main className="max-w-4xl mx-auto px-4 py-8">
        <div className="mb-6">
          <h1 className="text-xl font-semibold text-stone-900">Lixeira</h1>
          <p className="text-sm text-stone-500 mt-1">
            Entradas excluídas permanecem cifradas por até {RETENTION_DAYS} dias antes da remoção permanente.
          </p>
        </div>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2 mb-4">
            {error}
          </p>
        )}

        {loading ? (
          <p className="text-sm text-stone-500 text-center py-12">Carregando…</p>
        ) : entries.length === 0 ? (
          <div className="text-center py-16 border border-dashed border-stone-300 rounded-lg">
            <p className="text-stone-500 text-sm">A lixeira está vazia.</p>
          </div>
        ) : (
          <div className="border border-stone-200 rounded-lg bg-white overflow-hidden">
            <ul className="divide-y divide-stone-200">
              {entries.map((entry) => (
                <li key={entry.id} className="px-4 py-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-stone-900 truncate">{entry.title}</p>
                      {entry.site && (
                        <p className="text-xs text-stone-500 truncate mt-0.5">{entry.site}</p>
                      )}
                      <p className="text-xs text-amber-700 mt-1">
                        Excluída em {new Date(entry.deleted_at).toLocaleString('pt-BR')} · {remainingLabel(entry.purge_at)}
                      </p>
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <button
                        type="button"
                        onClick={() => restore(entry.id)}
                        disabled={action === entry.id}
                        className="text-xs px-2.5 py-1.5 rounded border border-stone-300 text-stone-700 hover:bg-stone-50 disabled:opacity-50"
                      >
                        Restaurar
                      </button>
                      <button
                        type="button"
                        onClick={() => permanentlyDelete(entry.id)}
                        disabled={action === entry.id}
                        className="text-xs px-2.5 py-1.5 rounded border border-red-200 text-red-700 hover:bg-red-50 disabled:opacity-50"
                      >
                        Excluir permanentemente
                      </button>
                    </div>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        )}
      </main>
    </div>
  )
}
