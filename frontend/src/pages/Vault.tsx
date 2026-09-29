import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, EntryListItem, WebAuthnDevice } from '../api'
import { getSessionRawKek } from '../crypto'
import { encryptKekWithPrf, getPrfForCredential, registerPasskey } from '../webauthn'
import { createEncryptedExport, decryptEncryptedExport, encryptPortableEntry } from '../export'

function expirationLabel(value: string | null): { text: string; className: string } | null {
  if (!value) return null
  const time = new Date(value).getTime()
  if (Number.isNaN(time)) return null
  const days = Math.ceil((time - Date.now()) / (24 * 60 * 60 * 1000))
  if (days <= 0) return { text: 'Expirada', className: 'text-red-700' }
  if (days <= 30) return { text: 'Expira em ' + days + 'd', className: 'text-amber-700' }
  return { text: 'Expira em ' + days + 'd', className: 'text-stone-400' }
}

export default function Vault() {
  const [entries, setEntries] = useState<EntryListItem[]>([])
  const [search, setSearch] = useState('')
  const [selectedTag, setSelectedTag] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [quickAccessLoading, setQuickAccessLoading] = useState(false)
  const [quickAccessMessage, setQuickAccessMessage] = useState('')
  const [quickAccessPending, setQuickAccessPending] = useState<{
    credentialId: string
    prfSalt: string
  } | null>(null)
  const [devices, setDevices] = useState<WebAuthnDevice[]>([])
  const [devicesLoading, setDevicesLoading] = useState(true)
  const [deviceAction, setDeviceAction] = useState<string | null>(null)
  const [transferBusy, setTransferBusy] = useState(false)
  const [transferMessage, setTransferMessage] = useState('')
  const nav = useNavigate()

  useEffect(() => {
    loadAll()
    loadDevices()
  }, [])

  async function loadDevices() {
    setDevicesLoading(true)
    try {
      const data = await api.webauthnDevices()
      setDevices(data.devices)
    } catch (err: any) {
      if (err.message?.includes('401') || err.message === 'invalid token') {
        api.logout()
        nav('/login')
        return
      }
    } finally {
      setDevicesLoading(false)
    }
  }

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

  async function registerQuickAccess() {
    setQuickAccessMessage('')
    setError('')
    setQuickAccessLoading(true)
    try {
      const registration = await api.webauthnRegisterOptions()
      const credential = await registerPasskey(registration.options)
      const verified = await api.webauthnRegisterVerify(
        registration.challenge,
        registration.prf_salt,
        credential,
      )
      setQuickAccessPending({
        credentialId: verified.credential_id,
        prfSalt: registration.prf_salt,
      })
      setQuickAccessMessage('Credencial salva. Clique em “Concluir ativação” para confirmar o acesso rápido neste dispositivo.')
    } catch (err: any) {
      setQuickAccessMessage('')
      setError(err.message || 'Não foi possível registrar a passkey')
    } finally {
      setQuickAccessLoading(false)
    }
  }

  async function renameDevice(device: WebAuthnDevice) {
    const proposed = window.prompt('Nome deste dispositivo/passkey:', device.name)
    if (proposed === null) return
    const name = proposed.trim()
    if (!name) {
      setError('O nome do dispositivo não pode ficar vazio')
      return
    }
    setDeviceAction(device.credential_id)
    setError('')
    try {
      const updated = await api.webauthnRenameDevice(device.credential_id, name)
      setDevices((current) =>
        current.map((item) =>
          item.credential_id === updated.credential_id ? updated : item,
        ),
      )
    } catch (err: any) {
      setError(err.message || 'Não foi possível renomear o dispositivo')
    } finally {
      setDeviceAction(null)
    }
  }

  async function revokeDevice(device: WebAuthnDevice) {
    const totp = window.prompt(
      'Para revogar esta passkey, digite o código TOTP atual:',
    )
    if (totp === null) return
    if (!/^\d{6}$/.test(totp)) {
      setError('Digite um código TOTP de 6 dígitos')
      return
    }
    setDeviceAction(device.credential_id)
    setError('')
    try {
      await api.webauthnRevokeDevice(device.credential_id, totp)
      setDevices((current) =>
        current.filter((item) => item.credential_id !== device.credential_id),
      )
    } catch (err: any) {
      setError(err.message || 'Não foi possível revogar o dispositivo')
    } finally {
      setDeviceAction(null)
    }
  }

  async function completeQuickAccess() {
    setQuickAccessMessage('')
    setError('')
    setQuickAccessLoading(true)
    try {
      if (!quickAccessPending) throw new Error('Nenhuma credencial aguardando ativação')
      const rawKek = getSessionRawKek()
      const prfOutput = await getPrfForCredential(
        quickAccessPending.credentialId,
        quickAccessPending.prfSalt,
      )
      const envelope = await encryptKekWithPrf(
        rawKek,
        prfOutput,
        quickAccessPending.credentialId,
      )
      await api.webauthnRegisterEnvelope(
        quickAccessPending.credentialId,
        envelope.encrypted_kek,
        envelope.kek_nonce,
      )
      setQuickAccessPending(null)
      await loadDevices()
      setQuickAccessMessage('Acesso rápido ativado. Nos próximos logins, use uma passkey confiável para abrir o cofre.')
    } catch (err: any) {
      setQuickAccessMessage('')
      setError(err.message || 'Não foi possível concluir o acesso rápido')
    } finally {
      setQuickAccessLoading(false)
    }
  }

  function logout() {
    api.logout()
    nav('/login')
  }

  async function exportVault() {
    setTransferBusy(true)
    setTransferMessage('')
    setError('')
    try {
      const password = window.prompt('Defina uma senha de exportação com pelo menos 12 caracteres:')
      if (password === null) return
      const confirmation = window.prompt('Digite novamente a senha de exportação:')
      if (confirmation === null) return
      if (password !== confirmation) throw new Error('As senhas de exportação não coincidem')
      if (password.length < 12) throw new Error('A senha de exportação deve ter pelo menos 12 caracteres')

      const summaries = await api.listEntries()
      const blobs = await Promise.all(summaries.map((entry) => api.getEntry(entry.id)))
      const serialized = await createEncryptedExport(blobs, password)
      const blob = new Blob([serialized], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = 'vaultlocal-export-' + new Date().toISOString().slice(0, 10) + '.json'
      anchor.click()
      URL.revokeObjectURL(url)
      setTransferMessage('Exportação cifrada criada. Guarde o arquivo e a senha separadamente.')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Não foi possível exportar o cofre')
    } finally {
      setTransferBusy(false)
    }
  }

  function importVault() {
    setTransferMessage('')
    setError('')
    const input = document.createElement('input')
    input.type = 'file'
    input.accept = '.json,application/json'
    input.onchange = async () => {
      const file = input.files?.[0]
      if (!file) return
      setTransferBusy(true)
      try {
        const password = window.prompt('Digite a senha usada para cifrar a exportação:')
        if (password === null) return
        const entries = await decryptEncryptedExport(await file.text(), password)
        const confirmed = window.confirm(
          'A exportação contém ' + entries.length + ' entrada(s). Elas serão adicionadas ao cofre atual sem substituir as existentes. Continuar?',
        )
        if (!confirmed) return
        for (const entry of entries) {
          await api.createEntry(await encryptPortableEntry(entry))
        }
        await loadAll()
        setTransferMessage(entries.length + ' entrada(s) importada(s) com nova criptografia.')
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Não foi possível importar a exportação')
      } finally {
        setTransferBusy(false)
      }
    }
    input.click()
  }


  const allTags = useMemo(() => {
    const set = new Set<string>()
    entries.forEach((e) => {
      if (e.tags) {
        e.tags
          .split(',')
          .map((t) => t.trim())
          .filter(Boolean)
          .forEach((t) => set.add(t))
      }
    })
    return Array.from(set).sort()
  }, [entries])

  const displayedEntries = useMemo(() => {
    if (!selectedTag) return entries
    return entries.filter((e) => {
      if (!e.tags) return false
      return e.tags
        .split(',')
        .map((t) => t.trim())
        .includes(selectedTag)
    })
  }, [entries, selectedTag])

  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-200 bg-white/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="text-lg font-semibold tracking-tight text-stone-900">
            Vault<span className="text-stone-400">Local</span>
          </Link>
          <div className="flex items-center gap-2 sm:gap-3">
            <button
              type="button"
              onClick={exportVault}
              disabled={transferBusy}
              className="text-xs sm:text-sm text-stone-500 hover:text-stone-900 disabled:opacity-50 transition"
            >
              Exportar
            </button>
            <button
              type="button"
              onClick={importVault}
              disabled={transferBusy}
              className="text-xs sm:text-sm text-stone-500 hover:text-stone-900 disabled:opacity-50 transition"
            >
              Importar
            </button>
            <Link
              to="/health"
              className="text-xs sm:text-sm text-stone-500 hover:text-stone-900 transition"
            >
              Saúde
            </Link>
            <Link
              to="/timeline"
              className="text-xs sm:text-sm text-stone-500 hover:text-stone-900 transition"
            >
              Timeline
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
        {transferMessage && (
          <p className="mb-4 text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md px-3 py-2">
            {transferMessage}
          </p>
        )}
        <div className="mb-4 rounded-lg border border-stone-200 bg-white px-4 py-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="text-sm font-medium text-stone-900">Acesso rápido com passkey</p>
              <p className="text-xs text-stone-500 mt-1">
                Use uma passkey, biometria ou PIN para abrir o cofre sem digitar a senha-mestra.
              </p>
              {quickAccessMessage && (
                <p className="text-xs text-emerald-700 mt-2">{quickAccessMessage}</p>
              )}
            </div>
            <button
              type="button"
              onClick={quickAccessPending ? completeQuickAccess : registerQuickAccess}
              disabled={quickAccessLoading}
              className="shrink-0 inline-flex items-center justify-center px-3 py-2 rounded-md border border-stone-300 bg-stone-50 text-stone-900 text-sm font-medium hover:bg-stone-100 disabled:opacity-50 transition"
            >
              {quickAccessLoading
                ? (quickAccessPending ? 'Concluindo…' : 'Registrando…')
                : (quickAccessPending ? 'Concluir ativação' : 'Ativar acesso rápido')}
            </button>
          </div>
        </div>

        <div className="mb-6 rounded-lg border border-stone-200 bg-white px-4 py-4">
          <div className="flex items-center justify-between gap-3 mb-3">
            <div>
              <p className="text-sm font-medium text-stone-900">Dispositivos confiáveis</p>
              <p className="text-xs text-stone-500 mt-1">
                Revogue uma passkey remotamente; a revogação exige seu TOTP atual.
              </p>
            </div>
            <span className="text-xs text-stone-400">{devices.length}</span>
          </div>
          {devicesLoading ? (
            <p className="text-xs text-stone-500">Carregando dispositivos…</p>
          ) : devices.length === 0 ? (
            <p className="text-xs text-stone-500">Nenhuma passkey confiável cadastrada.</p>
          ) : (
            <div className="space-y-2">
              {devices.map((device) => (
                <div
                  key={device.credential_id}
                  className="flex flex-col gap-2 rounded-md border border-stone-200 px-3 py-3 sm:flex-row sm:items-center sm:justify-between"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-stone-800 truncate">{device.name}</p>
                    <p className="text-xs text-stone-500 mt-1">
                      Criado em {new Date(device.created_at).toLocaleString("pt-BR")}
                      {device.last_used_at
                        ? ` · usado em ${new Date(device.last_used_at).toLocaleString("pt-BR")}`
                        : ''}
                      {device.credential_backed_up ? ' · sincronizado' : ' · neste autenticador'}
                    </p>
                  </div>
                  <div className="flex shrink-0 gap-2">
                    <button
                      type="button"
                      onClick={() => renameDevice(device)}
                      disabled={deviceAction === device.credential_id}
                      className="text-xs px-2.5 py-1.5 rounded border border-stone-300 text-stone-700 hover:bg-stone-50 disabled:opacity-50"
                    >
                      Renomear
                    </button>
                    <button
                      type="button"
                      onClick={() => revokeDevice(device)}
                      disabled={deviceAction === device.credential_id}
                      className="text-xs px-2.5 py-1.5 rounded border border-red-200 text-red-700 hover:bg-red-50 disabled:opacity-50"
                    >
                      {deviceAction === device.credential_id ? 'Processando…' : 'Revogar'}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="mb-4">
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar por título ou site…"
            className="w-full px-4 py-2.5 rounded-md border border-stone-300 bg-white text-stone-900 placeholder-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
          />
        </div>

        {allTags.length > 0 && (
          <div className="flex flex-wrap items-center gap-1.5 mb-6">
            <span className="text-xs text-stone-400 mr-1 font-medium">Tags:</span>
            <button
              type="button"
              onClick={() => setSelectedTag(null)}
              className={`text-xs px-2.5 py-1 rounded-full transition ${
                selectedTag === null
                  ? 'bg-stone-900 text-white font-medium'
                  : 'bg-stone-100 text-stone-600 hover:bg-stone-200'
              }`}
            >
              Todas
            </button>
            {allTags.map((tag) => (
              <button
                key={tag}
                type="button"
                onClick={() => setSelectedTag(selectedTag === tag ? null : tag)}
                className={`text-xs px-2.5 py-1 rounded-full transition ${
                  selectedTag === tag
                    ? 'bg-stone-900 text-white font-medium'
                    : 'bg-stone-100 text-stone-600 hover:bg-stone-200'
                }`}
              >
                {tag}
              </button>
            ))}
          </div>
        )}

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2 mb-4">
            {error}
          </p>
        )}

        {loading ? (
          <p className="text-sm text-stone-500 text-center py-12">Carregando…</p>
        ) : displayedEntries.length === 0 ? (
          <div className="text-center py-16 border border-dashed border-stone-300 rounded-lg">
            <p className="text-stone-500 text-sm">
              {search || selectedTag
                ? 'Nenhuma entrada encontrada'
                : 'Seu cofre está vazio'}
            </p>
            {!search && !selectedTag && (
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
            {displayedEntries.map((e) => (
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
                      {expirationLabel(e.expires_at) && (
                        <p className={"text-[11px] mt-1 " + expirationLabel(e.expires_at)!.className}>
                          {expirationLabel(e.expires_at)!.text}
                        </p>
                      )}
                    </div>
                    {e.tags && (
                      <div className="ml-4 flex gap-1.5 flex-shrink-0">
                        {e.tags
                          .split(',')
                          .map((t) => t.trim())
                          .filter(Boolean)
                          .map((t) => (
                            <button
                              key={t}
                              type="button"
                              onClick={(ev) => {
                                ev.preventDefault()
                                setSelectedTag(selectedTag === t ? null : t)
                              }}
                              className={`text-xs px-2 py-0.5 rounded-full border transition ${
                                selectedTag === t
                                  ? 'bg-stone-900 text-white border-stone-900'
                                  : 'bg-stone-100 text-stone-600 border-stone-200 hover:bg-stone-200'
                              }`}
                            >
                              {t}
                            </button>
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
