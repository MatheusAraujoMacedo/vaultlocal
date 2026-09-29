import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import { unwrapDataKey, decryptField, getSessionKek, buildDataKeyAad, buildFieldAad } from '../crypto'

interface CustomField {
  name: string
  value: string
}

interface PasswordHistoryItem {
  password: string
  changed_at: string
}

interface DecryptedEntry {
  id: string
  title: string
  site: string | null
  username: string
  password: string
  notes: string | null
  tags: string
  favorite: boolean
  passwordHistoryEnc: string | null
  noncePasswordHistory: string | null
  customFields: CustomField[]
}

export default function EntryDetail() {
  const { id } = useParams<{ id: string }>()
  const nav = useNavigate()
  const [entry, setEntry] = useState<DecryptedEntry | null>(null)
  const [showPassword, setShowPassword] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [passwordHistory, setPasswordHistory] = useState<PasswordHistoryItem[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!id) return
    ;(async () => {
      try {
        const e = await api.getEntry(id)
        const kek = getSessionKek()
        const dataKeyAad = e.crypto_version === 2 ? buildDataKeyAad(e.id) : undefined
        const key = await unwrapDataKey(
          { wrapped_data_key: e.wrapped_data_key, wrapped_nonce: e.wrapped_nonce },
          kek,
          dataKeyAad,
        )
        const username = await decryptField(
          { ciphertext: e.username_enc, nonce: e.nonce_username },
          key,
          e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'username') : undefined,
        )
        const password = await decryptField(
          { ciphertext: e.password_enc, nonce: e.nonce_password },
          key,
          e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'password') : undefined,
        )
        let customFields: CustomField[] = []
        if (e.custom_fields_enc && e.nonce_custom_fields) {
          const customFieldsJson = await decryptField(
            { ciphertext: e.custom_fields_enc, nonce: e.nonce_custom_fields },
            key,
            e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'custom_fields') : undefined,
          )
          try {
            const parsed = JSON.parse(customFieldsJson) as unknown
            if (Array.isArray(parsed)) {
              customFields = parsed.filter((item): item is CustomField =>
                !!item && typeof item === 'object' &&
                typeof (item as CustomField).name === 'string' &&
                typeof (item as CustomField).value === 'string',
              ).slice(0, 10)
            }
          } catch {
            customFields = []
          }
        }
        const notes = e.notes_enc
          ? await decryptField(
              { ciphertext: e.notes_enc, nonce: e.nonce_notes! },
              key,
              e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'notes') : undefined,
            )
          : null
        setEntry({
          id: e.id,
          title: e.title,
          site: e.site,
          username,
          password,
          notes,
          tags: e.tags,
          favorite: e.favorite,
          passwordHistoryEnc: e.password_history_enc,
          noncePasswordHistory: e.nonce_password_history,
          customFields,
        })
      } catch (err: any) {
        setError(err.message)
      }
    })()
  }, [id])

  async function loadHistory() {
    if (!entry?.passwordHistoryEnc || !entry.noncePasswordHistory || !id || !showHistory) return
    setHistoryLoading(true)
    try {
      const e = await api.getEntry(id)
      const kek = getSessionKek()
      const key = await unwrapDataKey(
        { wrapped_data_key: e.wrapped_data_key, wrapped_nonce: e.wrapped_nonce },
        kek,
        e.crypto_version === 2 ? buildDataKeyAad(e.id) : undefined,
      )
      if (!e.password_history_enc || !e.nonce_password_history) {
        throw new Error('Histórico de senhas indisponível')
      }
      const plaintext = await decryptField(
        { ciphertext: e.password_history_enc, nonce: e.nonce_password_history },
        key,
        e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'password_history') : undefined,
      )
      const parsed = JSON.parse(plaintext) as unknown
      if (!Array.isArray(parsed)) throw new Error('Histórico de senhas inválido')
      setPasswordHistory(parsed.filter((item): item is PasswordHistoryItem =>
        !!item && typeof item === 'object' &&
        typeof (item as PasswordHistoryItem).password === 'string' &&
        typeof (item as PasswordHistoryItem).changed_at === 'string',
      ).slice(0, 5))
    } catch (err: any) {
      setError(err.message)
      setShowHistory(false)
    } finally {
      setHistoryLoading(false)
    }
  }

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

  useEffect(() => {
    if (showHistory && passwordHistory.length === 0) void loadHistory()
  }, [showHistory])

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
          <div className="flex items-center justify-between gap-3">
            <h1 className="text-xl font-semibold text-stone-900">{entry.title}</h1>
            <button
              type="button"
              onClick={async () => {
                try {
                  const updated = await api.setFavorite(entry.id, !entry.favorite)
                  setEntry((current) => current ? { ...current, favorite: updated.favorite } : current)
                } catch (err: any) {
                  setError(err.message)
                }
              }}
              className="text-sm px-2.5 py-1.5 rounded-md border border-stone-300 text-stone-700 hover:bg-stone-50 transition"
              title={entry.favorite ? 'Remover dos favoritos' : 'Adicionar aos favoritos'}
            >
              {entry.favorite ? '★ Favorito' : '☆ Favoritar'}
            </button>
          </div>
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

          {entry.passwordHistoryEnc && (
            <div className="px-6 py-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-xs font-medium uppercase tracking-wide text-stone-500">Histórico de senhas</p>
                  <p className="text-xs text-stone-400 mt-1">Até 5 senhas anteriores, sempre cifradas no cofre.</p>
                </div>
                <button
                  type="button"
                  onClick={() => setShowHistory((value) => !value)}
                  className="text-xs px-2.5 py-1.5 rounded-md border border-stone-300 text-stone-700 hover:bg-stone-50"
                >
                  {showHistory ? 'Ocultar' : 'Ver histórico'}
                </button>
              </div>
              {showHistory && (
                <div className="mt-3 space-y-2">
                  {historyLoading ? (
                    <p className="text-xs text-stone-400">Descriptografando histórico…</p>
                  ) : passwordHistory.length === 0 ? (
                    <p className="text-xs text-stone-400">Nenhum histórico disponível.</p>
                  ) : passwordHistory.map((item) => (
                    <div key={item.changed_at} className="flex items-center justify-between gap-3 rounded-md border border-stone-200 px-3 py-2">
                      <div className="min-w-0">
                        <p className="font-mono text-xs text-stone-700 truncate">••••••••••••••••</p>
                        <p className="text-[11px] text-stone-400 mt-1">Alterada em {new Date(item.changed_at).toLocaleString('pt-BR')}</p>
                      </div>
                      <button type="button" onClick={() => copy(item.password)} className="shrink-0 text-xs px-2.5 py-1.5 rounded-md border border-stone-300 text-stone-700 hover:bg-stone-50">Copiar</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {entry.customFields.length > 0 && (
            <div className="px-6 py-4">
              <p className="text-xs font-medium uppercase tracking-wide text-stone-500 mb-2">Campos personalizados</p>
              <div className="space-y-2">
                {entry.customFields.map((field) => (
                  <Field key={field.name} label={field.name} value={field.value} onCopy={() => copy(field.value)} />
                ))}
              </div>
            </div>
          )}

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
