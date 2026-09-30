import { clearSessionKek } from './crypto'

const API_BASE = '/api/v1'
const TOKENS_KEY = 'vaultlocal_tokens'

type TokenBundle = {
  access: string | null
  refresh: string | null
}

function readTokens(): TokenBundle {
  try {
    const raw = sessionStorage.getItem(TOKENS_KEY)
    if (!raw) return { access: null, refresh: null }
    const parsed = JSON.parse(raw) as Partial<TokenBundle>
    return {
      access: typeof parsed.access === 'string' ? parsed.access : null,
      refresh: typeof parsed.refresh === 'string' ? parsed.refresh : null,
    }
  } catch {
    return { access: null, refresh: null }
  }
}

export function getAccessToken(): string | null {
  return readTokens().access
}

function getToken(): string | null {
  return getAccessToken()
}

export function setTokens(access: string, refresh: string) {
  sessionStorage.setItem(TOKENS_KEY, JSON.stringify({ access, refresh }))
}

export function clearTokens() {
  sessionStorage.removeItem(TOKENS_KEY)
}

async function request<T>(
  path: string,
  opts: RequestInit = {},
  auth = true,
): Promise<T> {
  const headers = new Headers(opts.headers)
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }
  if (auth) {
    const token = getToken()
    if (token) headers.set('Authorization', `Bearer ${token}`)
  }
  const res = await fetch(`${API_BASE}${path}`, { ...opts, headers })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

export interface EntryListItem {
  id: string
  title: string
  favorite: boolean
  site: string | null
  tags: string
  expires_at: string | null
  created_at: string
  updated_at: string
}

export interface TrashEntry extends EntryListItem {
  deleted_at: string
  purge_at: string
}

export interface EntryBlob extends EntryListItem {
  crypto_version: 1 | 2
  username_enc: string
  nonce_username: string
  password_enc: string
  nonce_password: string
  password_history_enc: string | null
  nonce_password_history: string | null
  custom_fields_enc: string | null
  nonce_custom_fields: string | null
  notes_enc: string | null
  nonce_notes: string | null
  wrapped_data_key: string
  wrapped_nonce: string
}

export type EntryWrite = Omit<EntryBlob, 'created_at' | 'updated_at'>

export interface LoginResult {
  status: 'mfa_setup_required' | 'recovery_setup_required' | 'mfa_verify_required'
  mfa_token: string
  recovery_upgrade_required: boolean
}

export interface GoogleHandoff {
  status: 'existing' | 'setup_required'
  email: string
  salt_auth?: string
  salt_crypto?: string
}

export interface WebAuthnRegisterOptions {
  options: Record<string, unknown>
  challenge: string
  prf_salt: string
}

export interface WebAuthnLoginOptions {
  options: Record<string, unknown>
  challenge: string
  prf_salts: Record<string, string>
}

export interface WebAuthnLoginResult {
  access_token: string
  refresh_token: string
  credential_id: string
  encrypted_kek: string
  kek_nonce: string
}

export interface WebAuthnDevice {
  credential_id: string
  name: string
  created_at: string
  last_used_at: string | null
  credential_backed_up: boolean
}

export interface WebAuthnDevicesResult {
  devices: WebAuthnDevice[]
}

export interface RecoveryInit {
  salt_crypto: string
  recovery_wrapped_kek: string
  recovery_nonce: string
  recovery_challenge: string
  recovery_public_key: string
  recovery_wrapped_signing_key: string
  recovery_signing_nonce: string
}

export interface RecoveryEntry {
  id: string
  crypto_version: 1 | 2
  wrapped_data_key: string
  wrapped_nonce: string
}

export interface RecoveryVerifyResult {
  recovery_token: string
  entries: RecoveryEntry[]
}

export interface Tokens {
  access_token: string
  refresh_token: string
}

export interface VaultSession {
  id: string
  created_at: string
  expires_at: string
  current: boolean
}

export interface SessionsResult {
  sessions: VaultSession[]
}

export interface TotpSetup {
  secret: string
  otpauth_uri: string
}

export interface HealthReportPayload {
  score: number
  total_entries: number
  weak_count: number
  reused_count: number
  old_count: number
  breached_count: number
}

export interface HealthReport extends HealthReportPayload {
  id: string
  user_id: string
  created_at: string
}

export type SecurityEventType =
  | 'login_success'
  | 'logout'
  | 'entry_created'
  | 'entry_updated'
  | 'entry_deleted'
  | 'entry_favorited'
  | 'entry_unfavorited'
  | 'health_scan'
  | 'passkey_added'
  | 'passkey_renamed'
  | 'passkey_revoked'
  | 'password_changed'
  | 'mfa_enabled'
  | 'recovery_used'
  | 'session_revoked'
  | 'sessions_revoked'

export interface SecurityEvent {
  event_type: SecurityEventType
  created_at: string
}

export const api = {
  loginInit: (email: string) =>
    request<{ salt_auth: string; salt_crypto: string }>('/auth/login/init', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }, false),

  register: (email: string, salt_auth: string, salt_crypto: string, auth_key: string) =>
    request<{ id: string; email: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, salt_auth, salt_crypto, auth_key }),
    }, false),

  login: (email: string, auth_key: string) =>
    request<LoginResult>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, auth_key }),
    }, false),

  googleLoginStart: () => {
    window.location.assign('/api/v1/auth/oidc/google/start')
  },

  googleLoginExchange: () =>
    request<GoogleHandoff>('/auth/oidc/google/exchange', {
      method: 'GET',
    }, false),

  googleLoginWithPassword: (auth_key: string) =>
    request<LoginResult>('/auth/oidc/google/password', {
      method: 'POST',
      body: JSON.stringify({ auth_key }),
    }, false),

  googleLoginComplete: (new_salt_auth: string, new_salt_crypto: string, auth_key: string) =>
    request<LoginResult>('/auth/oidc/google/complete', {
      method: 'POST',
      body: JSON.stringify({ new_salt_auth, new_salt_crypto, auth_key }),
    }, false),

  webauthnRegisterOptions: () =>
    request<WebAuthnRegisterOptions>('/auth/webauthn/register/options', {
      method: 'POST',
    }),

  webauthnRegisterVerify: (
    challenge: string,
    prf_salt: string,
    credential: Record<string, unknown>,
  ) =>
    request<{ credential_id: string; ready_for_envelope: boolean }>('/auth/webauthn/register/verify', {
      method: 'POST',
      body: JSON.stringify({ challenge, prf_salt, credential }),
    }),

  webauthnRegisterEnvelope: (
    credential_id: string,
    encrypted_kek: string,
    kek_nonce: string,
  ) =>
    request<void>('/auth/webauthn/register/envelope', {
      method: 'POST',
      body: JSON.stringify({ credential_id, encrypted_kek, kek_nonce }),
    }),

  webauthnDevices: () =>
    request<WebAuthnDevicesResult>('/auth/webauthn/devices'),

  webauthnRenameDevice: (credential_id: string, name: string) =>
    request<WebAuthnDevice>(`/auth/webauthn/devices/${encodeURIComponent(credential_id)}`, {
      method: 'PATCH',
      body: JSON.stringify({ name }),
    }),

  webauthnRevokeDevice: (credential_id: string, totp_code: string) =>
    request<void>(`/auth/webauthn/devices/${encodeURIComponent(credential_id)}/revoke`, {
      method: 'POST',
      body: JSON.stringify({ totp_code }),
    }),

  webauthnLocalOptions: (email: string) =>
    request<WebAuthnLoginOptions>('/auth/webauthn/local/options', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }, false),

  webauthnLocalDeviceOptions: (credential_id: string) =>
    request<WebAuthnLoginOptions>('/auth/webauthn/local/device/options', {
      method: 'POST',
      body: JSON.stringify({ credential_id }),
    }, false),

  webauthnLocalVerify: (
    challenge: string,
    credential: Record<string, unknown>,
  ) =>
    request<WebAuthnLoginResult>('/auth/webauthn/local/verify', {
      method: 'POST',
      body: JSON.stringify({ challenge, credential }),
    }, false),

  webauthnGoogleOptions: () =>
    request<WebAuthnLoginOptions>('/auth/webauthn/google/options', {
      method: 'GET',
    }, false),

  webauthnGoogleVerify: (
    challenge: string,
    credential: Record<string, unknown>,
  ) =>
    request<WebAuthnLoginResult>('/auth/webauthn/google/verify', {
      method: 'POST',
      body: JSON.stringify({ challenge, credential }),
    }, false),

  totpSetup: (mfa_token: string) =>
    request<TotpSetup>('/auth/totp/setup', {
      method: 'POST',
      headers: { Authorization: `Bearer ${mfa_token}` },
    }, false),

  totpConfirm: (mfa_token: string, totp_code: string) =>
    request<Tokens>('/auth/totp/confirm', {
      method: 'POST',
      headers: { Authorization: `Bearer ${mfa_token}` },
      body: JSON.stringify({ totp_code }),
    }, false),

  recoverySetup: (
    mfa_token: string,
    recovery_wrapped_kek: string,
    recovery_nonce: string,
    recovery_public_key: string,
    recovery_wrapped_signing_key: string,
    recovery_signing_nonce: string,
  ) =>
    request<void>('/auth/recovery/setup', {
      method: 'POST',
      headers: { Authorization: `Bearer ${mfa_token}` },
      body: JSON.stringify({
        recovery_wrapped_kek,
        recovery_nonce,
        recovery_public_key,
        recovery_wrapped_signing_key,
        recovery_signing_nonce,
      }),
    }, false),

  recoveryUpgrade: (
    access_token: string,
    recovery_public_key: string,
    recovery_wrapped_signing_key: string,
    recovery_signing_nonce: string,
  ) =>
    request<void>('/auth/recovery/upgrade', {
      method: 'POST',
      headers: { Authorization: `Bearer ${access_token}` },
      body: JSON.stringify({
        recovery_public_key,
        recovery_wrapped_signing_key,
        recovery_signing_nonce,
      }),
    }, false),

  recoveryInit: (email: string) =>
    request<RecoveryInit>('/auth/recovery/init', {
      method: 'POST',
      body: JSON.stringify({ email }),
    }, false),

  recoveryVerify: (
    email: string,
    recovery_challenge: string,
    recovery_proof: string,
  ) =>
    request<RecoveryVerifyResult>('/auth/recovery/verify', {
      method: 'POST',
      body: JSON.stringify({ email, recovery_challenge, recovery_proof }),
    }, false),

  recoveryRecover: (
    recovery_token: string,
    data: {
      new_auth_key: string
      new_salt_auth: string
      new_salt_crypto: string
      new_recovery_wrapped_kek: string
      new_recovery_nonce: string
      new_recovery_public_key: string
      new_recovery_wrapped_signing_key: string
      new_recovery_signing_nonce: string
      entries: Array<{ id: string; wrapped_data_key: string; wrapped_nonce: string }>
    },
  ) =>
    request<Tokens>('/auth/recovery/recover', {
      method: 'POST',
      headers: { Authorization: `Bearer ${recovery_token}` },
      body: JSON.stringify(data),
    }, false),

  mfaVerify: (mfa_token: string, totp_code: string) =>
    request<Tokens>('/auth/mfa/verify', {
      method: 'POST',
      headers: { Authorization: `Bearer ${mfa_token}` },
      body: JSON.stringify({ totp_code }),
    }, false),

  passwordResetRequest: (email: string, totp_code?: string) =>
    request<{ ok: boolean; token?: string }>('/auth/password-reset/request', {
      method: 'POST',
      body: JSON.stringify({ email, ...(totp_code ? { totp_code } : {}) }),
    }, false),

  passwordResetValidate: (token: string) =>
    request<{ ok: boolean }>('/auth/password-reset/validate', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }, false),

  passwordResetConfirm: (
    token: string,
    data: { new_auth_key: string; new_salt_auth: string; new_salt_crypto: string },
  ) =>
    request<void>('/auth/password-reset/confirm', {
      method: 'POST',
      body: JSON.stringify({ token, ...data }),
    }, false),

  logout: () => {
    const refresh = readTokens().refresh
    if (refresh) {
      request('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: refresh }),
      }, false).catch(() => {})
    }
    clearTokens()
    clearSessionKek()
  },

  listSessions: () => request<SessionsResult>('/auth/sessions'),

  revokeSession: (sessionId: string) =>
    request<void>('/auth/sessions/' + encodeURIComponent(sessionId) + '/revoke', {
      method: 'POST',
    }),

  revokeOtherSessions: () =>
    request<void>('/auth/sessions/revoke-others', {
      method: 'POST',
    }),

  listEntries: () => request<EntryListItem[]>('/entries'),

  getEntry: (id: string) => request<EntryBlob>(`/entries/${id}`),

  createEntry: (data: EntryWrite) =>
    request<EntryBlob>('/entries', { method: 'POST', body: JSON.stringify(data) }),

  updateEntry: (id: string, data: EntryWrite) =>
    request<EntryBlob>(`/entries/${id}`, { method: 'PUT', body: JSON.stringify(data) }),

  setFavorite: (id: string, favorite: boolean) =>
    request<EntryBlob>(`/entries/${id}/favorite`, {
      method: 'PATCH',
      body: JSON.stringify({ favorite }),
    }),

  deleteEntry: (id: string) =>
    request<void>(`/entries/${id}`, { method: 'DELETE' }),

  listTrash: () => request<TrashEntry[]>('/entries/trash'),

  restoreEntry: (id: string) =>
    request<EntryBlob>(`/entries/${id}/restore`, { method: 'POST' }),

  permanentlyDeleteEntry: (id: string) =>
    request<void>(`/entries/${id}/permanent`, { method: 'DELETE' }),

  search: (q: string) =>
    request<EntryListItem[]>(`/entries/search?q=${encodeURIComponent(q)}`),

  postHealthReport: (report: HealthReportPayload) =>
    request<{ id: string }>('/health/report', {
      method: 'POST',
      body: JSON.stringify(report),
    }),

  getLocalBreachStatus: () =>
    request<{ available: boolean; source: string }>('/health/breach/local/status'),

  getSecurityTimeline: (limit = 100) =>
    request<{ events: SecurityEvent[] }>(`/health/timeline?limit=${limit}`),

  getLatestHealth: async (): Promise<HealthReport | null> => {
    const token = getToken()
    const res = await fetch(`${API_BASE}/health/latest`, {
      headers: { Authorization: `Bearer ${token}` },
    })
    if (res.status === 404) return null
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || `HTTP ${res.status}`)
    }
    return res.json()
  },
}
