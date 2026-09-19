import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api, Entry } from '../api'

export default function EntryDetail() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const [entry, setEntry] = useState<Entry | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) return
    api
      .getEntry(id)
      .then(setEntry)
      .catch((e) => setError(e.message))
  }, [id])

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text)
      // clear after 30s
      setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30000)
    } catch {}
  }

  async function remove() {
    if (!id) return
    if (!confirm('Excluir esta entrada? Não há como desfazer.')) return
    try {
      await api.deleteEntry(id)
      nav('/')
    } catch (e: any) {
      setError(e.message)
    }
  }

  if (error) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-12">
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
          {error}
        </p>
        <Link to="/" className="block mt-4 text-sm text-stone-900 hover:underline">
          ← Voltar
        </Link>
      </div>
    )
  }

  if (!entry) {
    return <p className="text-sm text-stone-500 text-center py-12">Carregando…</p>
  }

  return (
    <div className="max-w-2xl mx-auto px-4 py-8">
      <Link to="/" className="text-sm text-stone-500 hover:text-stone-900 transition">
        ← Voltar
      </Link>

      <div className="mt-4 bg-white border border-stone-200 rounded-lg overflow-hidden">
        <div className="px-6 py-5 border-b border-stone-200">
          <h1 className="text-xl font-semibold text-stone-900">{entry.title}</h1>
          {entry.site && (
            <a
              href={entry.site.startsWith('http') ? entry.site : `https://${entry.site}`}
              target="_blank"
              rel="noreferrer"
              className="text-sm text-stone-500 hover:text-stone-900 hover:underline mt-0.5 inline-block"
            >
              {entry.site}
            </a>
          )}
        </div>

        <div className="divide-y divide-stone-100">
          <Field
            label="Usuário"
            value={entry.username}
            onCopy={() => copy(entry.username)}
          />

          <div className="px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium uppercase tracking-wide text-stone-500 mb-1">
                  Senha
                </p>
                <p className="font-mono text-sm text-stone-900 break-all">
                  {showPassword ? entry.password : '••••••••••••••••'}
                </p>
              </div>
              <div className="ml-4 flex gap-2">
                <button
                  onClick={() => setShowPassword((s) => !s)}
                  className="text-xs px-2.5 py-1.5 rounded-md border border-stone-300 text-stone-700 hover:bg-stone-50 transition"
                >
                  {showPassword ? 'Ocultar' : 'Mostrar'}
                </button>
                <button
                  onClick={() => copy(entry.password)}
                  className="text-xs px-2.5 py-1.5 rounded-md bg-stone-900 text-white hover:bg-stone-800 transition"
                >
                  Copiar
                </button>
              </div>
            </div>
          </div>

          {entry.notes && (
            <div className="px-6 py-4">
              <p className="text-xs font-medium uppercase tracking-wide text-stone-500 mb-1">
                Notas
              </p>
              <p className="text-sm text-stone-900 whitespace-pre-wrap">{entry.notes}</p>
            </div>
          )}

          {entry.tags && (
            <div className="px-6 py-4 flex gap-1.5 flex-wrap">
              {entry.tags.split(',').filter(Boolean).map((t) => (
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
      </div>

      <div className="mt-4 flex gap-3">
        <Link
          to={`/entry/${entry.id}/edit`}
          className="inline-flex items-center px-3 py-2 rounded-md border border-stone-300 text-sm font-medium text-stone-700 hover:bg-stone-50 transition"
        >
          Editar
        </Link>
        <button
          onClick={remove}
          className="inline-flex items-center px-3 py-2 rounded-md border border-red-300 text-sm font-medium text-red-700 hover:bg-red-50 transition"
        >
          Excluir
        </button>
      </div>
    </div>
  )
}

function Field({
  label,
  value,
  onCopy,
}: {
  label: string
  value: string
  onCopy?: () => void
}) {
  return (
    <div className="px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex-1 min-w-0">
          <p className="text-xs font-medium uppercase tracking-wide text-stone-500 mb-1">
            {label}
          </p>
          <p className="text-sm text-stone-900 break-all">{value}</p>
        </div>
        {onCopy && (
          <button
            onClick={onCopy}
            className="ml-4 text-xs px-2.5 py-1.5 rounded-md border border-stone-300 text-stone-700 hover:bg-stone-50 transition"
          >
            Copiar
          </button>
        )}
      </div>
    </div>
  )
}
