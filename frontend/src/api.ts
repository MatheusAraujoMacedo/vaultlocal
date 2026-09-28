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

function getToken(): string | null {
  return readTokens().access
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
  site: string | null
  tags: string
  created_at: string
  updated_at: string
}

export interface EntryBlob extends EntryListItem {
  crypto_version: 1 | 2
  username_enc: string
  nonce_username: string
  password_enc: string
  nonce_password: string
  notes_enc: string | null
  nonce_notes: string | null
  wrapped_data_key: string
  wrapped_nonce: string
}

export interface LoginResult {
  status: 'mfa_setup_required' | 'mfa_verify_required'
  mfa_token: string
}

export interface Tokens {
  access_token: string
  refresh_token: string
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
}

export interface HealthReport extends HealthReportPayload {
  id: string
  user_id: string
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

  mfaVerify: (mfa_token: string, totp_code: string) =>
    request<Tokens>('/auth/mfa/verify', {
      method: 'POST',
      headers: { Authorization: `Bearer ${mfa_token}` },
      body: JSON.stringify({ totp_code }),
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

  listEntries: () => request<EntryListItem[]>('/entries'),

  getEntry: (id: string) => request<EntryBlob>(`/entries/${id}`),

  createEntry: (data: Omit<EntryBlob, 'created_at' | 'updated_at'>) =>
    request<EntryBlob>('/entries', { method: 'POST', body: JSON.stringify(data) }),

  updateEntry: (id: string, data: Omit<EntryBlob, 'created_at' | 'updated_at'>) =>
    request<EntryBlob>(`/entries/${id}`, { method: 'PUT', body: JSON.stringify(data) }),

  deleteEntry: (id: string) =>
    request<void>(`/entries/${id}`, { method: 'DELETE' }),

  search: (q: string) =>
    request<EntryListItem[]>(`/entries/search?q=${encodeURIComponent(q)}`),

  generatePassword: (length = 20, use_symbols = true) =>
    request<{ password: string }>('/entries/generate/password', {
      method: 'POST',
      body: JSON.stringify({ length, use_symbols }),
    }),

  postHealthReport: (report: HealthReportPayload) =>
    request<{ id: string }>('/health/report', {
      method: 'POST',
      body: JSON.stringify(report),
    }),

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
