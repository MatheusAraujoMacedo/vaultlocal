import { useState, FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { deriveAuthKey, randomSaltB64, isCommonPassword } from '../crypto'

export default function Register() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const nav = useNavigate()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    if (password.length < 12) {
      setError('Senha-mestra precisa ter no mínimo 12 caracteres')
      return
    }
    if (isCommonPassword(password)) {
      setError('Senha-mestra é muito comum, escolha uma mais forte')
      return
    }
    if (password !== confirm) {
      setError('As senhas não coincidem')
      return
    }
    setLoading(true)
    try {
      const saltAuth = randomSaltB64()
      const saltCrypto = randomSaltB64()
      const authKey = await deriveAuthKey(password, saltAuth)
      await api.register(email, saltAuth, saltCrypto, authKey)
      // Cofre exige TOTP configurado antes de abrir (RFC Fase 1): o fluxo de
      // configuração vive na tela de login, não aqui.
      nav('/login')
    } catch (err: any) {
      setError(err.message || 'Erro ao criar conta')
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
          <p className="text-sm text-stone-500 mt-1">
            Crie seu cofre. A senha-mestra não pode ser recuperada.
          </p>
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
              placeholder="mínimo 12 caracteres"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-stone-700 mb-1.5">
              Confirmar senha-mestra
            </label>
            <input
              type="password"
              required
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 placeholder-stone-400 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
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
            className="w-full py-2.5 px-4 rounded-md bg-stone-900 text-white text-sm font-medium hover:bg-stone-800 disabled:opacity-50 transition"
          >
            {loading ? 'Criando…' : 'Criar cofre'}
          </button>
        </form>
        <p className="text-sm text-stone-500 text-center mt-6">
          Já tem uma conta?{' '}
          <Link to="/login" className="font-medium text-stone-900 hover:underline">
            Entrar
          </Link>
        </p>
      </div>
    </div>
  )
}
