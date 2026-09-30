import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, VaultSession, WebAuthnDevice } from '../api'
import { clearTrustedDeviceHint, getTrustedDeviceHint } from '../security/trustedDevice'

function formatDate(value: string): string {
  return new Date(value).toLocaleString('pt-BR', {
    dateStyle: 'short',
    timeStyle: 'short',
  })
}

export default function Sessions() {
  const [sessions, setSessions] = useState<VaultSession[]>([])
  const [devices, setDevices] = useState<WebAuthnDevice[]>([])
  const [loading, setLoading] = useState(true)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState('')
  const nav = useNavigate()

  async function load() {
    setLoading(true)
    setError('')
    try {
      const [result, deviceResult] = await Promise.all([
        api.listSessions(),
        api.webauthnDevices(),
      ])
      setSessions(result.sessions)
      setDevices(deviceResult.devices)
    } catch (err: any) {
      if (err.message?.includes('401') || err.message === 'invalid session') {
        api.logout()
        nav('/login')
        return
      }
      setError(err.message || 'Não foi possível carregar sessões e dispositivos')
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

  async function renameDevice(device: WebAuthnDevice) {
    const name = window.prompt('Novo nome para este dispositivo:', device.name)
    if (name === null) return
    const trimmed = name.trim()
    if (!trimmed || trimmed === device.name) return
    if (trimmed.length > 100) {
      setError('O nome do dispositivo deve ter no máximo 100 caracteres.')
      return
    }

    setBusy(`rename:${device.credential_id}`)
    setError('')
    try {
      const updated = await api.webauthnRenameDevice(device.credential_id, trimmed)
      setDevices((current) =>
        current.map((item) =>
          item.credential_id === device.credential_id ? updated : item,
        ),
      )
    } catch (err: any) {
      setError(err.message || 'Não foi possível renomear o dispositivo')
    } finally {
      setBusy(null)
    }
  }

  async function revokeDevice(device: WebAuthnDevice) {
    const code = window.prompt(
      `Revogar “${device.name}”? Isso desativa o desbloqueio rápido deste dispositivo. Digite o código TOTP de 6 dígitos para confirmar:`,
    )
    if (code === null) return
    const totp = code.trim()
    if (!/^\d{6}$/.test(totp)) {
      setError('Informe um código TOTP válido de 6 dígitos.')
      return
    }

    setBusy(`revoke:${device.credential_id}`)
    setError('')
    try {
      await api.webauthnRevokeDevice(device.credential_id, totp)
      setDevices((current) =>
        current.filter((item) => item.credential_id !== device.credential_id),
      )

      const hint = getTrustedDeviceHint()
      if (hint?.credentialId === device.credential_id) {
        clearTrustedDeviceHint()
      }
    } catch (err: any) {
      setError(err.message || 'Não foi possível revogar o dispositivo')
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
            <h1 className="text-lg font-semibold text-stone-900">Sessões e dispositivos</h1>
          </div>
          <Link to="/" className="text-sm text-stone-500 hover:text-stone-900">← Cofre</Link>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-4 py-8 space-y-8">
        {error && (
          <p className="text-sm text-red-700 bg-red-50 border border-red-200 rounded-md px-3 py-2">
            {error}
          </p>
        )}

        {loading ? (
          <p className="text-sm text-stone-500">Carregando sessões e dispositivos…</p>
        ) : (
          <>
            <section>
              <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                <div>
                  <h2 className="text-base font-semibold text-stone-900">Dispositivos confiáveis</h2>
                  <p className="text-xs text-stone-500 mt-1">
                    Passkeys autorizadas a desbloquear o cofre rapidamente neste dispositivo.
                  </p>
                </div>
              </div>

              {devices.length === 0 ? (
                <div className="rounded-lg border border-stone-200 bg-white px-4 py-5">
                  <p className="text-sm text-stone-600">Nenhum dispositivo confiável cadastrado.</p>
                  <p className="text-xs text-stone-400 mt-1">
                    Você pode cadastrar uma passkey nas configurações de segurança.
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  {devices.map((device) => {
                    const isBusy = busy === `rename:${device.credential_id}` || busy === `revoke:${device.credential_id}`
                    return (
                      <div key={device.credential_id} className="rounded-lg border border-stone-200 bg-white px-4 py-4">
                        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                          <div className="min-w-0">
                            <div className="flex flex-wrap items-center gap-2">
                              <p className="text-sm font-medium text-stone-900 truncate">{device.name}</p>
                              {device.credential_backed_up && (
                                <span className="text-[11px] px-2 py-0.5 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200">
                                  Sincronizada
                                </span>
                              )}
                            </div>
                            <p className="text-xs text-stone-500 mt-1">
                              Adicionado em {formatDate(device.created_at)}
                            </p>
                            <p className="text-xs text-stone-400 mt-0.5">
                              {device.last_used_at
                                ? `Usado pela última vez em ${formatDate(device.last_used_at)}`
                                : 'Ainda não utilizado'}
                            </p>
                          </div>
                          <div className="flex shrink-0 gap-2">
                            <button
                              type="button"
                              onClick={() => renameDevice(device)}
                              disabled={busy !== null}
                              className="px-3 py-1.5 rounded-md border border-stone-300 text-xs text-stone-700 hover:bg-stone-50 disabled:opacity-50"
                            >
                              {busy === `rename:${device.credential_id}` ? 'Salvando…' : 'Renomear'}
                            </button>
                            <button
                              type="button"
                              onClick={() => revokeDevice(device)}
                              disabled={busy !== null}
                              className="px-3 py-1.5 rounded-md border border-red-200 text-xs text-red-700 hover:bg-red-50 disabled:opacity-50"
                            >
                              {busy === `revoke:${device.credential_id}` ? 'Revogando…' : 'Revogar'}
                            </button>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </section>

            <section>
              <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                <div>
                  <h2 className="text-base font-semibold text-stone-900">Sessões ativas</h2>
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

              {sessions.length === 0 ? (
                <p className="text-sm text-stone-500">Nenhuma sessão ativa encontrada.</p>
              ) : (
                <div className="space-y-3">
                  {sessions.map((session) => (
                    <div key={session.id} className="rounded-lg border border-stone-200 bg-white px-4 py-4">
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
            </section>
          </>
        )}

        <p className="text-xs text-stone-400">
          Revogar um dispositivo remove a passkey autorizada para o desbloqueio rápido; revogar uma sessão encerra apenas aquela sessão. Nenhuma dessas ações expõe o conteúdo cifrado do cofre.
        </p>
      </main>
    </div>
  )
}
