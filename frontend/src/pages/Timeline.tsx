import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, SecurityEvent, SecurityEventType } from '../api'

const EVENT_LABELS: Record<SecurityEventType, string> = {
  entry_created: 'Entrada adicionada ao cofre',
  entry_updated: 'Entrada atualizada',
  entry_deleted: 'Entrada removida',
  entry_favorited: 'Entrada adicionada aos favoritos',
  entry_unfavorited: 'Entrada removida dos favoritos',
  health_scan: 'Auditoria de segurança executada',
  passkey_added: 'Novo dispositivo confiável adicionado',
  passkey_renamed: 'Dispositivo confiável renomeado',
  passkey_revoked: 'Dispositivo confiável revogado',
  password_changed: 'Senha-mestra alterada',
  mfa_enabled: 'Autenticação em dois fatores ativada',
  recovery_used: 'Recovery Key utilizada',
  login_success: 'Login concluído',
  logout: 'Sessão encerrada',
  session_revoked: 'Sessão revogada',
  sessions_revoked: 'Outras sessões revogadas',
}

function formatEventTime(value: string): string {
  return new Date(value).toLocaleString('pt-BR', {
    dateStyle: 'medium',
    timeStyle: 'short',
  })
}

function eventMarker(type: SecurityEventType): string {
  if (type === 'entry_deleted' || type === 'passkey_revoked') return '!'
  if (type === 'recovery_used') return 'R'
  if (type === 'login_success') return 'L'
  if (type === 'logout') return 'S'
  if (type === 'password_changed' || type === 'mfa_enabled') return 'S'
  return '•'
}

export default function Timeline() {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const nav = useNavigate()

  useEffect(() => {
    let active = true
    ;(async () => {
      try {
        const result = await api.getSecurityTimeline()
        if (active) setEvents(result.events)
      } catch (err: any) {
        if (err?.message?.includes('401') || err?.message === 'invalid token') {
          api.logout()
          nav('/login')
          return
        }
        if (active) setError(err?.message || 'Não foi possível carregar a timeline')
      } finally {
        if (active) setLoading(false)
      }
    })()
    return () => {
      active = false
    }
  }, [nav])

  return (
    <div className="min-h-screen">
      <header className="border-b border-stone-200 bg-white/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-3xl mx-auto px-4 py-4 flex items-center justify-between">
          <Link to="/" className="text-lg font-semibold tracking-tight text-stone-900">
            Vault<span className="text-stone-400">Local</span>
          </Link>
          <Link to="/" className="text-sm text-stone-500 hover:text-stone-900">
            ← Cofre
          </Link>
        </div>
      </header>

      <main className="max-w-3xl mx-auto px-4 py-8">
        <div className="mb-8">
          <p className="text-xs font-medium uppercase tracking-wider text-stone-400">Security Timeline</p>
          <h1 className="text-2xl font-semibold text-stone-900 mt-1">Histórico de segurança</h1>
          <p className="text-sm text-stone-500 mt-2">
            Eventos administrativos e de proteção do cofre. Segredos nunca são registrados aqui.
          </p>
        </div>

        {error && (
          <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2 mb-5">
            {error}
          </p>
        )}

        {loading ? (
          <p className="text-sm text-stone-500 py-12 text-center">Carregando histórico…</p>
        ) : events.length === 0 ? (
          <div className="border border-dashed border-stone-300 rounded-lg py-14 text-center">
            <p className="text-sm text-stone-500">Nenhum evento registrado ainda.</p>
            <p className="text-xs text-stone-400 mt-1">
              Alterações no cofre aparecerão aqui.
            </p>
          </div>
        ) : (
          <div className="relative ml-2 border-l border-stone-200 pl-6 space-y-5">
            {events.map((event, index) => (
              <article key={event.created_at + '-' + index} className="relative">
                <div className="absolute -left-[2rem] top-1 w-6 h-6 rounded-full border border-stone-200 bg-white flex items-center justify-center text-[10px] font-semibold text-stone-500">
                  {eventMarker(event.event_type)}
                </div>
                <div className="rounded-lg border border-stone-200 bg-white px-4 py-3">
                  <p className="text-sm font-medium text-stone-900">
                    {EVENT_LABELS[event.event_type]}
                  </p>
                  <time className="text-xs text-stone-400 mt-1 block">
                    {formatEventTime(event.created_at)}
                  </time>
                </div>
              </article>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}
