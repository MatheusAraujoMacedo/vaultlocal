import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, EntryListItem } from '../api'

export default function Vault() {
  const [entries, setEntries] = useState<EntryListItem[]>([])
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const nav = useNavigate()

  useEffect(() => {
    loadAll()
  }, [])

  async function loadAll() {
    setLoading(true)
    try {
      const data = await api.listEntries()
      setEntries(data)
    } catch (err: any) {
      if (err.message?.includes('401') || err.message === 'invalid token') {
        api.logout()
        nav('/login')
        return
      }
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    const t = setTimeout(async () => {
      if (!search.trim()) {
        loadAll()
        return
      }
      try {
        const data = await api.search(search)
        setEntries(data)
      } catch {
        /* ignore */
      }
    }, 250)
    return () => clearTimeout(t)
  }, [search])

  function logout() {
    api.logout()
    nav('/login')
  }

  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-200 bg-white/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="text-lg font-semibold tracking-tight text-stone-900">
            Vault<span className="text-stone-400">Local</span>
          </Link>
          <div className="flex items-center gap-3">
            <Link
              to="/health"
              className="text-sm text-stone-500 hover:text-stone-900 transition"
            >
              Saúde
            </Link>
            <Link
              to="/entry/new"
              className="inline-flex items-center px-3 py-1.5 rounded-md bg-stone-900 text-white text-sm font-medium hover:bg-stone-800 transition"
            >
              Nova entrada
            </Link>
            <button
              onClick={logout}
              className="text-sm text-stone-500 hover:text-stone-900 transition"
            >
              Sair
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-4xl mx-auto px-4 py-8">
        <div className="mb-6">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar por título ou site…"
            className="w-full px-4 py-2.5 rounded-md border border-stone-300 bg-white text-stone-900 placeholder-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
          />
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
            <p className="text-stone-500 text-sm">
              {search ? 'Nenhuma entrada encontrada' : 'Seu cofre está vazio'}
            </p>
            {!search && (
              <Link
                to="/entry/new"
                className="inline-block mt-3 text-sm font-medium text-stone-900 hover:underline"
              >
                Adicionar primeira senha →
              </Link>
            )}
          </div>
        ) : (
          <ul className="divide-y divide-stone-200 border border-stone-200 rounded-lg bg-white overflow-hidden">
            {entries.map((e) => (
              <li key={e.id}>
                <Link
                  to={`/entry/${e.id}`}
                  className="block px-4 py-3.5 hover:bg-stone-50 transition"
                >
                  <div className="flex items-center justify-between">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-stone-900 truncate">
                        {e.title}
                      </p>
                      {e.site && (
                        <p className="text-xs text-stone-500 truncate mt-0.5">
                          {e.site}
                        </p>
                      )}
                    </div>
                    {e.tags && (
                      <div className="ml-4 flex gap-1.5 flex-shrink-0">
                        {e.tags.split(',').filter(Boolean).map((t) => (
                          <span
                            key={t}
                            className="text-xs px-2 py-0.5 rounded-full bg-stone-100 text-stone-600 border border-stone-200"
                          >
                            {t}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </Link>
              </li>
            ))}
          </ul>
        )}
      </main>
    </div>
  )
}
