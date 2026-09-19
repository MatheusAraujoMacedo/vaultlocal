import { useState, FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, setTokens } from '../api'
import { deriveAuthKey, deriveKek, setSessionKek, clearSessionKek } from '../crypto'

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  async function submit(e: FormEvent) {
    e.preventDefault()
    clearSessionKek()
    setError('')
    setLoading(true)
    try {
      const salts = await api.loginInit(email)
      const authKey = await deriveAuthKey(password, salts.salt_auth)
      const kek = await deriveKek(password, salts.salt_crypto)
      const res = await api.login(email, authKey)
      setTokens(res.access_token, res.refresh_token)
      setSessionKek(kek)
      onLogin()
      nav('/')
    } catch (err: any) {
      setError(err.message || 'Erro ao entrar')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="mb-10 text-center">
          <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
            Vault<span className="text-stone-400">Local</span>
          </h1>
          <p className="text-sm text-stone-500 mt-1">Seu cofre de senhas local</p>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-stone-700 mb-1.5">
              E-mail
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 placeholder-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
              placeholder="voce@exemplo.com"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-stone-700 mb-1.5">
              Senha-mestra
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 placeholder-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
              placeholder="••••••••••••"
            />
          </div>
          {error && (
            <p className="text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
              {error}
            </p>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 rounded-md bg-stone-900 text-white text-sm font-medium hover:bg-stone-800 active:bg-stone-950 disabled:opacity-50 transition"
          >
            {loading ? 'Entrando…' : 'Entrar'}
          </button>
        </form>
        <p className="text-sm text-stone-500 text-center mt-6">
          Ainda não tem conta?{' '}
          <Link to="/register" className="font-medium text-stone-900 hover:underline">
            Criar cofre
          </Link>
        </p>
      </div>
    </div>
  )
}
