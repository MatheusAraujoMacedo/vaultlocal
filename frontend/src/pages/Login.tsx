import { useState, FormEvent, useEffect } from 'react'
import { Link, useNavigate, useLocation } from 'react-router-dom'
import QRCode from 'qrcode'
import { api, setTokens } from '../api'
import {
  deriveAuthKey,
  deriveKek,
  deriveRawKek,
  generateRecoveryKey,
  generateRecoverySigningMaterial,
  recoveryKeyFromDisplay,
  recoveryKeyToDisplay,
  unwrapKekWithRecoveryKey,
  rawKekToCryptoKey,
  setSessionKek,
  setSessionRawKek,
  clearSessionKek,
  wrapKekWithRecoveryKey,
} from '../crypto'
import {
  authenticatePasskey,
  decryptKekWithPrf,
} from '../webauthn'

type Stage = 'credentials' | 'google-setup' | 'recovery-setup' | 'recovery-upgrade' | 'totp-setup' | 'totp-verify'

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
  const [rawKek, setRawKek] = useState<Uint8Array | null>(null)
  const [recoveryDisplay, setRecoveryDisplay] = useState('')
  const [recoveryConfirm, setRecoveryConfirm] = useState('')
  const [needsTotpSetup, setNeedsTotpSetup] = useState(false)
  const [needsRecoveryUpgrade, setNeedsRecoveryUpgrade] = useState(false)
  const [pendingSessionTokens, setPendingSessionTokens] = useState<{ access_token: string; refresh_token: string } | null>(null)
  const [migrationRecoveryKey, setMigrationRecoveryKey] = useState('')
  const [googlePasswordConfirm, setGooglePasswordConfirm] = useState('')
  const [googleAuthSalts, setGoogleAuthSalts] = useState<{ salt_auth: string; salt_crypto: string } | null>(null)
  const [googlePasskeyOptions, setGooglePasskeyOptions] = useState<{
    options: Record<string, unknown>
    challenge: string
    prf_salts: Record<string, string>
  } | null>(null)
  const nav = useNavigate()
  const location = useLocation()

  useEffect(() => {
    const state = location.state as { registered?: boolean; email?: string } | null
    const params = new URLSearchParams(location.search)
    const google = params.get('google') === '1'
    const oauthError = params.get('oauth_error')

    if (state?.registered) {
      setInfo('Conta criada. Entre com seu e-mail e senha-mestra para configurar o autenticador.')
      if (state.email) setEmail(state.email)
      nav(location.pathname, { replace: true, state: null })
      return
    }

    if (oauthError) {
      setError('Não foi possível concluir o login com Google.')
      nav('/login', { replace: true })
      return
    }

    if (google) {
      setLoading(true)
      api.googleLoginExchange()
        .then(async (handoff) => {
          setEmail(handoff.email)
          if (handoff.status === 'existing' && handoff.salt_auth && handoff.salt_crypto) {
            setGoogleAuthSalts({ salt_auth: handoff.salt_auth, salt_crypto: handoff.salt_crypto })
            try {
              const passkey = await api.webauthnGoogleOptions()
              setGooglePasskeyOptions(passkey)
              setInfo('Google confirmou sua identidade. Desbloqueie com a passkey deste dispositivo ou use a senha-mestra.')
            } catch {
              setGooglePasskeyOptions(null)
              setInfo('Identidade Google confirmada. Agora informe sua senha-mestra para destravar o cofre.')
            }
            nav('/login', { replace: true })
          } else {
            setPassword('')
            setGooglePasswordConfirm('')
            setStage('google-setup')
            nav('/login', { replace: true })
          }
        })
        .catch((err: any) => {
          setError(err.message || 'Sessão Google expirada')
          nav('/login', { replace: true })
        })
        .finally(() => setLoading(false))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function submitGoogleSetup(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (password.length < 12) throw new Error('Use uma senha-mestra com pelo menos 12 caracteres')
      if (password !== googlePasswordConfirm) throw new Error('As senhas-mestras não coincidem')

      const saltAuthBytes = crypto.getRandomValues(new Uint8Array(16))
      const saltCryptoBytes = crypto.getRandomValues(new Uint8Array(16))
      const saltAuth = btoa(String.fromCharCode(...saltAuthBytes))
      const saltCrypto = btoa(String.fromCharCode(...saltCryptoBytes))
      const authKey = await deriveAuthKey(password, saltAuth)
      const derivedKek = await deriveKek(password, saltCrypto)
      const derivedRawKek = await deriveRawKek(password, saltCrypto)

      const result = await api.googleLoginComplete(saltAuth, saltCrypto, authKey)
      setKek(derivedKek)
      setRawKek(derivedRawKek)
      setMfaToken(result.mfa_token)
      setNeedsTotpSetup(true)
      const recoveryKey = generateRecoveryKey()
      setRecoveryDisplay(recoveryKeyToDisplay(recoveryKey))
      setRecoveryConfirm('')
      setStage('recovery-setup')
    } catch (err: any) {
      setError(err.message || 'Não foi possível criar o cofre Google')
    } finally {
      setLoading(false)
    }
  }

  async function submitCredentials(e: FormEvent) {
    e.preventDefault()
    clearSessionKek()
    setError('')
    setLoading(true)
    try {
      const salts = googleAuthSalts ?? await api.loginInit(email)
      const authKey = await deriveAuthKey(password, salts.salt_auth)
      const derivedKek = await deriveKek(password, salts.salt_crypto)
      const derivedRawKek = await deriveRawKek(password, salts.salt_crypto)
      setKek(derivedKek)
      setRawKek(derivedRawKek)
      const res = googleAuthSalts
        ? await api.googleLoginWithPassword(authKey)
        : await api.login(email, authKey)
      setGoogleAuthSalts(null)
      setMfaToken(res.mfa_token)
      setNeedsRecoveryUpgrade(res.recovery_upgrade_required)

      if (res.status === 'mfa_setup_required' || res.status === 'recovery_setup_required') {
        setNeedsTotpSetup(res.status === 'mfa_setup_required')
        const recoveryKey = generateRecoveryKey()
        setRecoveryDisplay(recoveryKeyToDisplay(recoveryKey))
        setRecoveryConfirm('')
        setStage('recovery-setup')
      } else {
        setStage('totp-verify')
      }
    } catch (err: any) {
      setError(err.message || 'Erro ao entrar')
    } finally {
      setLoading(false)
    }
  }

  async function completeLogin(tokens: { access_token: string; refresh_token: string }) {
    setTokens(tokens.access_token, tokens.refresh_token)
    if (kek) setSessionKek(kek)
    if (rawKek) setSessionRawKek(rawKek)
    onLogin()
    nav('/')
  }

  function backToCredentials(msg?: string) {
    setStage('credentials')
    setError(msg ?? '')
    setGooglePasskeyOptions(null)
    setTotpCode('')
    setMfaToken('')
    setGoogleAuthSalts(null)
  }

  async function submitPasskeyLogin() {
    clearSessionKek()
    setError('')
    setLoading(true)
    try {
      const options = googlePasskeyOptions ?? await api.webauthnLocalOptions(email)
      const auth = await authenticatePasskey(options.options, options.prf_salts)
      const result = googlePasskeyOptions
        ? await api.webauthnGoogleVerify(options.challenge, auth.credential)
        : await api.webauthnLocalVerify(options.challenge, auth.credential)
      const raw = await decryptKekWithPrf(
        result.encrypted_kek,
        result.kek_nonce,
        auth.prfOutput,
        result.credential_id,
      )
      const unlockedKek = await rawKekToCryptoKey(raw)
      setSessionRawKek(raw)
      setSessionKek(unlockedKek)
      setTokens(result.access_token, result.refresh_token)
      onLogin()
      nav('/')
    } catch (err: any) {
      const message = err.message || 'Não foi possível desbloquear com a passkey'
      setError(message.includes('no trusted device')
        ? 'Nenhuma passkey confiável está cadastrada para este e-mail.'
        : message)
    } finally {
      setLoading(false)
    }
  }

  function isExpiredMfaErr(err: any): boolean {
    const msg: string = err?.message ?? ''
    return msg.includes('expired') || msg.includes('invalid or expired') || msg.includes('mfa token')
  }

  async function submitRecoverySetup(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (!rawKek || !recoveryDisplay || recoveryDisplay !== recoveryConfirm) {
        throw new Error('Digite novamente a recovery key exatamente como exibida')
      }
      const recoveryKey = recoveryKeyFromDisplay(recoveryDisplay)
      const wrapped = await wrapKekWithRecoveryKey(rawKek, recoveryKey)
      const signing = await generateRecoverySigningMaterial(recoveryKey)
      await api.recoverySetup(
        mfaToken,
        wrapped.recovery_wrapped_kek,
        wrapped.recovery_nonce,
        signing.recovery_public_key,
        signing.recovery_wrapped_signing_key,
        signing.recovery_signing_nonce,
      )

      // A chave é exibida somente nesta tela; depois do salvamento ela é removida da UI.
      setRecoveryDisplay('')
      setRecoveryConfirm('')
      if (needsTotpSetup) {
        const setup = await api.totpSetup(mfaToken)
        setTotpSecret(setup.secret)
        setQrDataUrl(await QRCode.toDataURL(setup.otpauth_uri))
        setStage('totp-setup')
      } else {
        setStage('totp-verify')
      }
    } catch (err: any) {
      if (err?.message?.includes('recovery key already configured')) {
        setStage(needsTotpSetup ? 'totp-setup' : 'totp-verify')
      } else if (err?.message?.includes('mfa token') || err?.message?.includes('expired')) {
        backToCredentials('Sessão expirada. Identifique-se novamente.')
      } else {
        setError(err.message || 'Não foi possível salvar a recovery key')
      }
    } finally {
      setLoading(false)
    }
  }

  async function submitRecoveryUpgrade(e: FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (!rawKek || !pendingSessionTokens || !migrationRecoveryKey) {
        throw new Error('Recovery Key necessária para concluir a migração')
      }
      const init = await api.recoveryInit(email)
      const recoveryKey = recoveryKeyFromDisplay(migrationRecoveryKey)
      const recoveredRawKek = await unwrapKekWithRecoveryKey(
        {
          recovery_wrapped_kek: init.recovery_wrapped_kek,
          recovery_nonce: init.recovery_nonce,
        },
        recoveryKey,
      )
      if (recoveredRawKek.length !== rawKek.length || recoveredRawKek.some((byte, i) => byte !== rawKek[i])) {
        throw new Error('Recovery Key não corresponde ao cofre atual')
      }
      const signing = await generateRecoverySigningMaterial(recoveryKey)
      await api.recoveryUpgrade(
        pendingSessionTokens.access_token,
        signing.recovery_public_key,
        signing.recovery_wrapped_signing_key,
        signing.recovery_signing_nonce,
      )
      setMigrationRecoveryKey('')
      const tokens = pendingSessionTokens
      setPendingSessionTokens(null)
      completeLogin(tokens)
    } catch (err: any) {
      setError(err.message || 'Não foi possível migrar a recovery key')
    } finally {
      setLoading(false)
    }
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
      if (needsRecoveryUpgrade) {
        setPendingSessionTokens(tokens)
        setMigrationRecoveryKey('')
        setStage('recovery-upgrade')
      } else {
        completeLogin(tokens)
      }
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

  if (stage === 'google-setup') {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="w-full max-w-sm">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
              Criar senha-mestra
            </h1>
            <p className="text-sm text-stone-500 mt-1">
              Sua conta Google identifica você; esta senha continua sendo a chave do seu cofre.
            </p>
          </div>
          <div className="rounded-md border border-stone-200 bg-stone-50 p-4 mb-5">
            <p className="text-xs text-stone-500">Conta Google confirmada</p>
            <p className="text-sm font-medium text-stone-900 break-all mt-1">{email}</p>
          </div>
          <form onSubmit={submitGoogleSetup} className="space-y-4">
            <label className="block text-sm font-medium text-stone-700">
              Senha-mestra
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                minLength={12}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
                autoComplete="new-password"
              />
            </label>
            <label className="block text-sm font-medium text-stone-700">
              Confirme a senha-mestra
              <input
                type="password"
                required
                value={googlePasswordConfirm}
                onChange={(e) => setGooglePasswordConfirm(e.target.value)}
                minLength={12}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent transition"
                autoComplete="new-password"
              />
            </label>
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
              {loading ? 'Criando cofre…' : 'Continuar'}
            </button>
          </form>
        </div>
      </div>
    )
  }

  if (stage === 'recovery-setup') {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="w-full max-w-lg">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
              Sua recovery key
            </h1>
            <p className="text-sm text-stone-500 mt-1">
              Ela é a única forma de recuperar o cofre sem apagar suas entradas.
            </p>
          </div>
          <div className="rounded-md border border-amber-200 bg-amber-50 p-4 mb-5">
            <p className="text-sm text-amber-900 font-medium">
              Salve esta chave em um local seguro. Ela não será exibida novamente.
            </p>
          </div>
          <div className="rounded-md bg-stone-100 border border-stone-200 p-4 mb-5">
            <p className="font-mono text-sm leading-7 text-stone-900 break-words text-center select-all">
              {recoveryDisplay}
            </p>
          </div>
          <form onSubmit={submitRecoverySetup} className="space-y-4">
            <label className="block text-sm font-medium text-stone-700">
              Digite a recovery key novamente para confirmar
              <input
                type="text"
                required
                value={recoveryConfirm}
                onChange={(e) => setRecoveryConfirm(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white font-mono text-sm focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
                placeholder="Cole a chave exatamente como acima"
                autoComplete="off"
              />
            </label>
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
              {loading ? 'Salvando…' : 'Salvar recovery key e continuar'}
            </button>
          </form>
        </div>
      </div>
    )
  }

  if (stage === 'recovery-upgrade') {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="w-full max-w-lg">
          <div className="mb-6 text-center">
            <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
              Atualizar recovery key
            </h1>
            <p className="text-sm text-stone-500 mt-1">
              Esta conta tem uma recovery key antiga. Digite a mesma chave uma vez para ativar a recuperação sem TOTP.
            </p>
          </div>
          <div className="rounded-md border border-amber-200 bg-amber-50 p-4 mb-5">
            <p className="text-sm text-amber-900">
              Sua recovery key não será substituída. Ela só ganhará uma nova prova criptográfica de posse.
            </p>
          </div>
          <form onSubmit={submitRecoveryUpgrade} className="space-y-4">
            <label className="block text-sm font-medium text-stone-700">
              Recovery key atual
              <textarea
                required
                value={migrationRecoveryKey}
                onChange={(e) => setMigrationRecoveryKey(e.target.value)}
                rows={3}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
                placeholder="XXXX XXXX XXXX ..."
                autoComplete="off"
              />
            </label>
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
              {loading ? 'Atualizando…' : 'Ativar recovery sem TOTP'}
            </button>
          </form>
        </div>
      </div>
    )
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
          {(googlePasskeyOptions || email.includes('@')) && (
            <button
              type="button"
              onClick={submitPasskeyLogin}
              disabled={loading}
              className="w-full py-2.5 px-4 rounded-md border border-stone-300 bg-stone-50 text-stone-900 text-sm font-medium hover:bg-stone-100 disabled:opacity-50 transition"
            >
              {loading
                ? 'Autenticando…'
                : (googlePasskeyOptions ? 'Desbloquear com este dispositivo' : 'Entrar com passkey')}
            </button>
          )}
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
        <div className="flex items-center gap-3 my-5">
          <div className="h-px flex-1 bg-stone-200" />
          <span className="text-xs text-stone-400">ou</span>
          <div className="h-px flex-1 bg-stone-200" />
        </div>
        <button
          type="button"
          onClick={() => api.googleLoginStart()}
          disabled={loading}
          className="w-full py-2.5 px-4 rounded-md border border-stone-300 bg-white text-stone-900 text-sm font-medium hover:bg-stone-50 disabled:opacity-50 transition"
        >
          Continuar com Google
        </button>
        <div className="text-center mt-6 space-y-2">
          <Link to="/forgot-password" className="block text-sm font-medium text-stone-900 hover:underline">
            Esqueci a senha-mestra
          </Link>
          <p className="text-sm text-stone-500">
            Ainda não tem conta?{' '}
            <Link to="/register" className="font-medium text-stone-900 hover:underline">
              Criar cofre
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
