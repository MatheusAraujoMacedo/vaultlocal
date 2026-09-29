import { useEffect, useState, FormEvent } from 'react'

import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import {
  generateDataKey, wrapDataKey, unwrapDataKey, encryptField, decryptField, getSessionKek,
  buildDataKeyAad, buildFieldAad, generateSecurePassword,
} from '../crypto'

interface CustomField {
  name: string
  value: string
}

interface PasswordHistoryItem {
  password: string
  changed_at: string
}

function toDateTimeLocal(value: string): string {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return ''
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60_000)
  return local.toISOString().slice(0, 16)
}

export default function EntryForm() {
  const { id } = useParams<{ id: string }>()
  const isEdit = !!id
  const nav = useNavigate()
  const [searchParams] = useSearchParams()
  const issue = searchParams.get('issue')

  const [title, setTitle] = useState('')
  const [site, setSite] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [notes, setNotes] = useState('')
  const [tags, setTags] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [favorite, setFavorite] = useState(false)
  const [originalPassword, setOriginalPassword] = useState('')
  const [passwordHistory, setPasswordHistory] = useState<PasswordHistoryItem[]>([])
  const [customFields, setCustomFields] = useState<CustomField[]>([])
  const [error, setError] = useState('')
  const [loadError, setLoadError] = useState('')
  const [loading, setLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [dataKey, setDataKey] = useState<CryptoKey | null>(null)

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
        setDataKey(key)
        setTitle(e.title)
        setSite(e.site || '')
        setUsername(await decryptField(
          { ciphertext: e.username_enc, nonce: e.nonce_username },
          key,
          e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'username') : undefined,
        ))
        const decryptedPassword = await decryptField(
          { ciphertext: e.password_enc, nonce: e.nonce_password },
          key,
          e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'password') : undefined,
        )
        if (e.custom_fields_enc) {
          const customFieldsJson = await decryptField(
            { ciphertext: e.custom_fields_enc, nonce: e.nonce_custom_fields! },
            key,
            e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'custom_fields') : undefined,
          )
          try {
            const parsed = JSON.parse(customFieldsJson) as unknown
            if (Array.isArray(parsed)) {
              setCustomFields(parsed.filter((item): item is CustomField =>
                !!item && typeof item === 'object' &&
                typeof (item as CustomField).name === 'string' &&
                typeof (item as CustomField).value === 'string',
              ).slice(0, 10))
            }
          } catch {
            setCustomFields([])
          }
        }
        setPassword(decryptedPassword)
        setOriginalPassword(decryptedPassword)
        if (e.password_history_enc) {
          const historyJson = await decryptField(
            { ciphertext: e.password_history_enc, nonce: e.nonce_password_history! },
            key,
            e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'password_history') : undefined,
          )
          try {
            const parsed = JSON.parse(historyJson) as unknown
            if (Array.isArray(parsed)) {
              setPasswordHistory(parsed.filter((item): item is PasswordHistoryItem =>
                !!item && typeof item === 'object' &&
                typeof (item as PasswordHistoryItem).password === 'string' &&
                typeof (item as PasswordHistoryItem).changed_at === 'string',
              ).slice(0, 5))
            }
          } catch {
            setPasswordHistory([])
          }
        }
        setNotes(
          e.notes_enc
            ? await decryptField(
                { ciphertext: e.notes_enc, nonce: e.nonce_notes! },
                key,
                e.crypto_version === 2 ? buildFieldAad(e.id, e.title, e.site, 'notes') : undefined,
              )
            : '',
        )
        setTags(e.tags)
        setExpiresAt(e.expires_at ? toDateTimeLocal(e.expires_at) : '')
        setFavorite(e.favorite)
      } catch (err: any) {
        setLoadError(err.message)
      }
    })()
  }, [id])

  async function submit(ev: FormEvent) {
    ev.preventDefault()
    setError('')
    setLoading(true)
    try {
      const kek = getSessionKek()
      const entryId = id ?? crypto.randomUUID()
      const storedSite = site || null
      const key = dataKey || (await generateDataKey())
      const wrapped = await wrapDataKey(key, kek, buildDataKeyAad(entryId))
      const u = await encryptField(username, key, buildFieldAad(entryId, title, storedSite, 'username'))
      const p = await encryptField(password, key, buildFieldAad(entryId, title, storedSite, 'password'))
      const n = notes
        ? await encryptField(notes, key, buildFieldAad(entryId, title, storedSite, 'notes'))
        : null
      const nextHistory = isEdit && password !== originalPassword && originalPassword
        ? [{ password: originalPassword, changed_at: new Date().toISOString() }, ...passwordHistory].slice(0, 5)
        : passwordHistory
      const history = nextHistory.length
        ? await encryptField(JSON.stringify(nextHistory), key, buildFieldAad(entryId, title, storedSite, 'password_history'))
        : null

      const customFieldsPayload = customFields
        .filter((field) => field.name.trim() || field.value)
        .slice(0, 10)
      const customFieldsCipher = customFieldsPayload.length
        ? await encryptField(JSON.stringify(customFieldsPayload), key, buildFieldAad(entryId, title, storedSite, 'custom_fields'))
        : null

      const data = {
        id: entryId,
        crypto_version: 2 as const,
        title,
        site: storedSite,
        username_enc: u.ciphertext,
        nonce_username: u.nonce,
        password_enc: p.ciphertext,
        nonce_password: p.nonce,
        password_history_enc: history ? history.ciphertext : null,
        nonce_password_history: history ? history.nonce : null,
        custom_fields_enc: customFieldsCipher ? customFieldsCipher.ciphertext : null,
        nonce_custom_fields: customFieldsCipher ? customFieldsCipher.nonce : null,
        notes_enc: n ? n.ciphertext : null,
        nonce_notes: n ? n.nonce : null,
        wrapped_data_key: wrapped.wrapped_data_key,
        wrapped_nonce: wrapped.wrapped_nonce,
        tags,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
        favorite,
      }
      if (isEdit) {
        await api.updateEntry(id!, data)
      } else {
        await api.createEntry(data)
      }
      nav(issue ? '/health' : '/')
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function generate() {
    setGenerating(true)
    try {
      setPassword(generateSecurePassword(24, true))
    } catch (e: any) {
      setError(e.message)
    } finally {
      setGenerating(false)
    }
  }

  if (isEdit && loadError) {
    return (
      <div className="max-w-2xl mx-auto px-4 py-12">
        <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
          {loadError}
        </p>
        <Link to="/" className="block mt-4 text-sm text-stone-900 hover:underline">
          ← Voltar
        </Link>
      </div>
    )
  }

  return (
    <div className="max-w-2xl mx-auto px-4 py-8">
      <Link to={isEdit ? `/entry/${id}` : '/'} className="text-sm text-stone-500 hover:text-stone-900 transition">
        ← Voltar
      </Link>

      <h1 className="text-xl font-semibold text-stone-900 mt-4 mb-6">
        {isEdit ? 'Editar entrada' : 'Nova entrada'}
      </h1>

      {issue && (
        <div className="p-3.5 mb-5 bg-amber-50 border border-amber-200 rounded-md text-sm text-amber-800 flex items-center justify-between">
          <span>
            Problema detectado na auditoria ({issue}). Use o botão <strong>Gerar</strong> para definir uma nova senha forte.
          </span>
        </div>
      )}

      <form onSubmit={submit} className="space-y-5">
        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">Título</label>
          <input
            type="text"
            required
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
            placeholder="Ex.: GitHub, Gmail, Banco…"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">Site</label>
          <input
            type="text"
            value={site}
            onChange={(e) => setSite(e.target.value)}
            className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
            placeholder="exemplo.com"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">Usuário</label>
          <input
            type="text"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">Senha</label>
          <div className="flex gap-2">
            <input
              type="text"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="flex-1 px-3 py-2 rounded-md border border-stone-300 bg-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
            />
            <button
              type="button"
              onClick={generate}
              disabled={generating}
              className={
                issue
                  ? 'px-3 py-2 rounded-md bg-stone-900 text-white text-sm font-medium hover:bg-stone-800 transition disabled:opacity-50'
                  : 'px-3 py-2 rounded-md border border-stone-300 text-sm text-stone-700 hover:bg-stone-50 transition disabled:opacity-50'
              }
            >
              {generating ? '…' : 'Gerar'}
            </button>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">Notas</label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            rows={3}
            className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
          />
        </div>

        <div className="rounded-md border border-stone-200 bg-stone-50 px-3 py-3">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-medium text-stone-700">Campos personalizados</p>
              <p className="text-xs text-stone-400 mt-0.5">Nome e valor ficam cifrados no navegador.</p>
            </div>
            <button
              type="button"
              disabled={customFields.length >= 10}
              onClick={() => setCustomFields((fields) => [...fields, { name: '', value: '' }])}
              className="text-xs px-2.5 py-1.5 rounded-md border border-stone-300 text-stone-700 hover:bg-white disabled:opacity-50"
            >
              + Campo
            </button>
          </div>
          {customFields.length > 0 && (
            <div className="mt-3 space-y-2">
              {customFields.map((field, index) => (
                <div key={index} className="flex gap-2">
                  <input
                    value={field.name}
                    onChange={(e) => setCustomFields((fields) => fields.map((item, i) => i === index ? { ...item, name: e.target.value } : item))}
                    placeholder="Nome"
                    maxLength={100}
                    className="w-1/3 px-3 py-2 rounded-md border border-stone-300 bg-white text-sm"
                  />
                  <input
                    value={field.value}
                    onChange={(e) => setCustomFields((fields) => fields.map((item, i) => i === index ? { ...item, value: e.target.value } : item))}
                    placeholder="Valor"
                    maxLength={1000}
                    className="flex-1 px-3 py-2 rounded-md border border-stone-300 bg-white text-sm"
                  />
                  <button
                    type="button"
                    onClick={() => setCustomFields((fields) => fields.filter((_, i) => i !== index))}
                    className="px-2 text-xs text-red-700 hover:bg-red-50 rounded"
                    aria-label="Remover campo"
                  >
                    Remover
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex items-center justify-between rounded-md border border-stone-200 bg-stone-50 px-3 py-2.5">
          <div>
            <p className="text-sm font-medium text-stone-700">Favorito</p>
            <p className="text-xs text-stone-400 mt-0.5">Fixe esta entrada para encontrá-la rapidamente.</p>
          </div>
          <button
            type="button"
            onClick={() => setFavorite((value) => !value)}
            className={`text-sm px-3 py-1.5 rounded-md border transition ${favorite ? 'bg-stone-900 text-white border-stone-900' : 'border-stone-300 text-stone-700 hover:bg-white'}`}
          >
            {favorite ? '★ Favorito' : '☆ Favoritar'}
          </button>
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Expiração <span className="text-stone-400 font-normal">(opcional)</span>
          </label>
          <input
            type="datetime-local"
            value={expiresAt}
            min={toDateTimeLocal(new Date().toISOString())}
            onChange={(e) => setExpiresAt(e.target.value)}
            className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
          />
          <p className="text-xs text-stone-400 mt-1.5">
            O lembrete é um metadado do cofre; nenhuma senha é armazenada em claro.
          </p>
        </div>

        <div>
          <label className="block text-sm font-medium text-stone-700 mb-1.5">
            Tags <span className="text-stone-400 font-normal">(separadas por vírgula)</span>
          </label>
          <input
            type="text"
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
            placeholder="pessoal, trabalho"
          />
        </div>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
            {error}
          </p>
        )}

        <div className="flex gap-3 pt-2">
          <button
            type="submit"
            disabled={loading}
            className="px-4 py-2 rounded-md bg-stone-900 text-white text-sm font-medium hover:bg-stone-800 disabled:opacity-50 transition"
          >
            {loading ? 'Salvando…' : isEdit ? 'Salvar alterações' : 'Adicionar'}
          </button>
          <Link
            to={isEdit ? `/entry/${id}` : '/'}
            className="px-4 py-2 rounded-md border border-stone-300 text-sm text-stone-700 hover:bg-stone-50 transition"
          >
            Cancelar
          </Link>
        </div>
      </form>
    </div>
  )
}
