const API_BASE = '/api/v1'

function getToken(): string | null {
  return localStorage.getItem('access_token')
}

export function setTokens(access: string, refresh: string) {
  localStorage.setItem('access_token', access)
  localStorage.setItem('refresh_token', refresh)
}

export function clearTokens() {
  localStorage.removeItem('access_token')
  localStorage.removeItem('refresh_token')
}

async function request<T>(
  path: string,
  opts: RequestInit = {},
  auth = true,
): Promise<T> {
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(opts.headers || {}),
  }
  if (auth) {
    const token = getToken()
    if (token) headers['Authorization'] = `Bearer ${token}`
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

export interface Entry extends EntryListItem {
  username: string
  password: string
  notes: string | null
}

export const api = {
  register: (email: string, master_password: string) =>
    request<{ id: string; email: string }>('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, master_password }),
    }, false),

  login: (email: string, master_password: string) =>
    request<{ access_token: string; refresh_token: string }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, master_password }),
    }, false),

  logout: () => {
    const refresh = localStorage.getItem('refresh_token')
    if (refresh) {
      request('/auth/logout', {
        method: 'POST',
        body: JSON.stringify({ refresh_token: refresh }),
      }, false).catch(() => {})
    }
    clearTokens()
  },

  listEntries: () => request<EntryListItem[]>('/entries'),

  getEntry: (id: string) => request<Entry>(`/entries/${id}`),

  createEntry: (data: Omit<Entry, 'id' | 'created_at' | 'updated_at'>) =>
    request<Entry>('/entries', { method: 'POST', body: JSON.stringify(data) }),

  updateEntry: (id: string, data: Omit<Entry, 'id' | 'created_at' | 'updated_at'>) =>
    request<Entry>(`/entries/${id}`, { method: 'PUT', body: JSON.stringify(data) }),

  deleteEntry: (id: string) =>
    request<void>(`/entries/${id}`, { method: 'DELETE' }),

  search: (q: string) =>
    request<EntryListItem[]>(`/entries/search?q=${encodeURIComponent(q)}`),

  generatePassword: (length = 20, use_symbols = true) =>
    request<{ password: string }>('/entries/generate/password', {
      method: 'POST',
      body: JSON.stringify({ length, use_symbols }),
    }),
}
