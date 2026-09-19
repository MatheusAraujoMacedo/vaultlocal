import { useEffect, useState, FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { api } from '../api'
import {
  generateDataKey, wrapDataKey, unwrapDataKey, encryptField, decryptField, getSessionKek,
} from '../crypto'

export default function EntryForm() {
  const { id } = useParams<{ id: string }>()
  const isEdit = !!id
  const nav = useNavigate()

  const [title, setTitle] = useState('')
  const [site, setSite] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [notes, setNotes] = useState('')
  const [tags, setTags] = useState('')
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
        const key = await unwrapDataKey(
          { wrapped_data_key: e.wrapped_data_key, wrapped_nonce: e.wrapped_nonce },
          kek,
        )
        setDataKey(key)
        setTitle(e.title)
        setSite(e.site || '')
        setUsername(await decryptField({ ciphertext: e.username_enc, nonce: e.nonce_username }, key))
        setPassword(await decryptField({ ciphertext: e.password_enc, nonce: e.nonce_password }, key))
        setNotes(
          e.notes_enc
            ? await decryptField({ ciphertext: e.notes_enc, nonce: e.nonce_notes! }, key)
            : '',
        )
        setTags(e.tags)
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
      const key = dataKey || (await generateDataKey())
      const wrapped = await wrapDataKey(key, kek)
      const u = await encryptField(username, key)
      const p = await encryptField(password, key)
      const n = notes ? await encryptField(notes, key) : null

      const data = {
        title,
        site: site || null,
        username_enc: u.ciphertext,
        nonce_username: u.nonce,
        password_enc: p.ciphertext,
        nonce_password: p.nonce,
        notes_enc: n ? n.ciphertext : null,
        nonce_notes: n ? n.nonce : null,
        wrapped_data_key: wrapped.wrapped_data_key,
        wrapped_nonce: wrapped.wrapped_nonce,
        tags,
      }
      if (isEdit) {
        await api.updateEntry(id!, data)
      } else {
        await api.createEntry(data)
      }
      nav('/')
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  async function generate() {
    setGenerating(true)
    try {
      const res = await api.generatePassword(24, true)
      setPassword(res.password)
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
              className="px-3 py-2 rounded-md border border-stone-300 text-sm text-stone-700 hover:bg-stone-50 transition disabled:opacity-50"
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
