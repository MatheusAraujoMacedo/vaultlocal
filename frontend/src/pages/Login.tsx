import { useState, FormEvent, useEffect } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import QRCode from 'qrcode'
import { api, setTokens } from '../api'
import { deriveAuthKey, deriveKek, setSessionKek, clearSessionKek } from '../crypto'

type Stage = 'credentials' | 'totp-setup' | 'totp-verify'

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [loading, setLoading] = useState(false)
  const [stage, setStage] = useState<Stage>('credentials')
  const [mfaToken, setMfaToken] = useState('')
  const [totpSecret, setTotpSecret] = useState('')
  const [qrDataUrl, setQrDataUrl] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [kek, setKek] = useState<CryptoKey | null>(null)
  const nav = useNavigate()
  const location = useLocation()

  useEffect(() => {
    const state = location.state as { registered?: boolean; email?: string } | null
    if (state?.registered) {
      setInfo('Conta criada. Entre com seu e-mail e senha-mestra para configurar o autenticador.')
      if (state.email) setEmail(state.email)
      // limpa o state para não reaparecer em navegação
      nav(location.pathname, { replace: true, state: null })
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function submitCredentials(e: FormEvent) {
    e.preventDefault()
    clearSessionKek()
    setError('')
    setLoading(true)
    try {
      const salts = await api.loginInit(email)
      const authKey = await deriveAuthKey(password, salts.salt_auth)
      const derivedKek = await deriveKek(password, salts.salt_crypto)
      setKek(derivedKek)
      const res = await api.login(email, authKey)
      setMfaToken(res.mfa_token)
      if (res.status === 'mfa_setup_required') {
        const setup = await api.totpSetup(res.mfa_token)
        setTotpSecret(setup.secret)
        setQrDataUrl(await QRCode.toDataURL(setup.otpauth_uri))
        setStage('totp-setup')
      } else {
        setStage('totp-verify')
      }
    } catch (err: any) {
      setError(err.message || 'Erro ao entrar')
    } finally {
      setLoading(false)
    }
  }

  function completeLogin(tokens: { access_token: string; refresh_token: string }) {
    setTokens(tokens.access_token, tokens.refresh_token)
    if (kek) setSessionKek(kek)
    onLogin()
    nav('/')
  }

  function backToCredentials(msg?: string) {
    setStage('credentials')
    setError(msg ?? '')
    setTotpCode('')
    setMfaToken('')
  }

  function isExpiredMfaErr(err: any): boolean {
    const msg: string = err?.message ?? ''
    return msg.includes('expired') || msg.includes('invalid or expired') || msg.includes('mfa token')
  }

  async function submitTotpSetup(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const tokens = await api.totpConfirm(mfaToken, totpCode)
      completeLogin(tokens)
    } catch (err: any) {
      if (isExpiredMfaErr(err)) {
        backToCredentials('Sessão expirada. Identifique-se novamente.')
      } else {
        setError(err.message || 'Código inválido')
      }
    } finally {
      setLoading(false)
    }
  }

  async function submitTotpVerify(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const tokens = await api.mfaVerify(mfaToken, totpCode)
      completeLogin(tokens)
    } catch (err: any) {
      if (isExpiredMfaErr(err)) {
        backToCredentials('Sessão expirada. Identifique-se novamente.')
      } else {
        setError(err.message || 'Código inválido')
      }
    } finally {
      setLoading(false)
    }
  }

  if (stage === 'totp-setup') {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="w-full max-w-sm">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
              Configurar autenticação
            </h1>
            <p className="text-sm text-stone-500 mt-1">
              Escaneie com Google Authenticator, Authy ou similar
            </p>
          </div>
          {qrDataUrl && <img src={qrDataUrl} alt="QR code TOTP" className="mx-auto mb-4" />}
          <p className="text-xs text-stone-500 text-center mb-4 break-all">{totpSecret}</p>
          <form onSubmit={submitTotpSetup} className="space-y-4">
            <input
              type="text"
              inputMode="numeric"
              required
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 text-center tracking-widest focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
              placeholder="000000"
              maxLength={6}
            />
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
              {loading ? 'Confirmando…' : 'Confirmar'}
            </button>
            <button
              type="button"
              onClick={() => backToCredentials()}
              className="w-full text-center text-xs text-stone-500 hover:text-stone-900 mt-3 transition"
            >
              ← Voltar para identificação
            </button>
          </form>
        </div>
      </div>
    )
  }

  if (stage === 'totp-verify') {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="w-full max-w-sm">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
              Código de verificação
            </h1>
            <p className="text-sm text-stone-500 mt-1">Digite o código do seu app autenticador</p>
          </div>
          <form onSubmit={submitTotpVerify} className="space-y-4">
            <input
              type="text"
              inputMode="numeric"
              required
              value={totpCode}
              onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="w-full px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 text-center tracking-widest focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
              placeholder="000000"
              maxLength={6}
            />
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
            <button
              type="button"
              onClick={() => backToCredentials()}
              className="w-full text-center text-xs text-stone-500 hover:text-stone-900 mt-3 transition"
            >
              ← Voltar para identificação
            </button>
          </form>
        </div>
      </div>
    )
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
        <form onSubmit={submitCredentials} className="space-y-4">
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
          {info && (
            <p className="text-sm text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-md px-3 py-2">
              {info}
            </p>
          )}
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
