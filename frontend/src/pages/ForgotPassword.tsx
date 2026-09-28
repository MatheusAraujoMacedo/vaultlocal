import { FormEvent, ReactNode, useEffect, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import {
  deriveAuthKey,
  deriveRawKek,
  generateRecoveryKey,
  generateRecoverySigningMaterial,
  randomSaltB64,
  recoveryKeyFromDisplay,
  recoveryKeyToDisplay,
  recoveryProof,
  rawKekToCryptoKey,
  unwrapDataKey,
  unwrapKekWithRecoveryKey,
  wrapDataKey,
  wrapKekWithRecoveryKey,
  buildDataKeyAad,
} from '../crypto'

type Stage =
  | 'choice'
  | 'recovery-key'
  | 'recovery-password'
  | 'recovery-confirm'
  | 'reset-request'
  | 'reset-confirm'

export default function ForgotPassword() {
  const [stage, setStage] = useState<Stage>('choice')
  const [email, setEmail] = useState('')
  const [recoveryKey, setRecoveryKey] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newPasswordConfirm, setNewPasswordConfirm] = useState('')
  const [ack, setAck] = useState('')
  const [resetToken, setResetToken] = useState('')
  const [oldRawKek, setOldRawKek] = useState<Uint8Array | null>(null)
  const [recoveryChallenge, setRecoveryChallenge] = useState('')
  const [recoverySigningKeyWrap, setRecoverySigningKeyWrap] = useState({
    recovery_wrapped_signing_key: '',
    recovery_signing_nonce: '',
  })
  const [pendingRecovery, setPendingRecovery] = useState<any>(null)
  const [newRecoveryDisplay, setNewRecoveryDisplay] = useState('')
  const [newRecoveryConfirm, setNewRecoveryConfirm] = useState('')
  const [error, setError] = useState('')
  const [info, setInfo] = useState('')
  const [loading, setLoading] = useState(false)
  const [searchParams] = useSearchParams()
  const nav = useNavigate()

  useEffect(() => {
    const token = searchParams.get('reset')
    if (!token) return
    setResetToken(token)
    setLoading(true)
    api.passwordResetValidate(token)
      .then(() => setStage('reset-confirm'))
      .catch((err) => setError(err.message || 'Link de reset inválido ou expirado'))
      .finally(() => setLoading(false))
  }, [searchParams])

  function passwordIsValid(password: string) {
    if (password.length < 12) {
      setError('Senha-mestra precisa ter no mínimo 12 caracteres')
      return false
    }
    if (password !== newPasswordConfirm) {
      setError('As senhas não coincidem')
      return false
    }
    return true
  }

  function chooseRecovery() {
    setError('')
    setInfo('A recovery key correta permite trocar a senha sem apagar o cofre.')
    setStage('recovery-key')
  }

  function chooseReset() {
    setError('')
    setInfo('Este caminho apaga permanentemente as entradas atuais do cofre.')
    setStage('reset-request')
  }
  async function submitRecoveryKey(ev: FormEvent) {
    ev.preventDefault()
    setError('')
    setLoading(true)
    try {
      const init = await api.recoveryInit(email)
      const key = recoveryKeyFromDisplay(recoveryKey)
      const raw = await unwrapKekWithRecoveryKey(
        {
          recovery_wrapped_kek: init.recovery_wrapped_kek,
          recovery_nonce: init.recovery_nonce,
        },
        key,
      )
      if (!init.recovery_public_key || !init.recovery_wrapped_signing_key || !init.recovery_signing_nonce || init.recovery_public_key === '{}') {
        throw new Error('Esta Recovery Key precisa ser ativada uma vez pelo login normal antes da recuperação sem TOTP.')
      }
      setOldRawKek(raw)
      setRecoveryChallenge(init.recovery_challenge)
      setRecoverySigningKeyWrap({
        recovery_wrapped_signing_key: init.recovery_wrapped_signing_key,
        recovery_signing_nonce: init.recovery_signing_nonce,
      })
      setTotpCode('')
      setStage('recovery-password')
    } catch (err: any) {
      setError('Recovery key inválida ou não disponível para esta conta.')
    } finally {
      setLoading(false)
    }
  }

  async function submitRecoveryPassword(ev: FormEvent) {
    ev.preventDefault()
    setError('')
    if (!passwordIsValid(newPassword)) return
    setLoading(true)
    try {
      if (!recoveryChallenge || !recoveryKey) throw new Error('material de recovery ausente')
      const recoveryKeyBytes = recoveryKeyFromDisplay(recoveryKey)
      const proof = await recoveryProof(
        recoveryKeyBytes,
        recoverySigningKeyWrap.recovery_wrapped_signing_key,
        recoverySigningKeyWrap.recovery_signing_nonce,
        recoveryChallenge,
      )
      const verified = await api.recoveryVerify(
        email,
        recoveryChallenge,
        proof,
      )
      if (!oldRawKek) throw new Error('material de recovery ausente')
      const oldKey = await rawKekToCryptoKey(oldRawKek)
      const newSaltAuth = randomSaltB64()
      const newSaltCrypto = randomSaltB64()
      const newAuthKey = await deriveAuthKey(newPassword, newSaltAuth)
      const newRawKek = await deriveRawKek(newPassword, newSaltCrypto)
      const newKek = await rawKekToCryptoKey(newRawKek)
      const entries = []
      for (const entry of verified.entries) {
        const aad = entry.crypto_version === 2 ? buildDataKeyAad(entry.id) : undefined
        const dataKey = await unwrapDataKey(
          { wrapped_data_key: entry.wrapped_data_key, wrapped_nonce: entry.wrapped_nonce },
          oldKey,
          aad,
        )
        const wrapped = await wrapDataKey(dataKey, newKek, aad)
        entries.push({
          id: entry.id,
          wrapped_data_key: wrapped.wrapped_data_key,
          wrapped_nonce: wrapped.wrapped_nonce,
        })
      }
      const nextRecoveryKey = generateRecoveryKey()
      const nextWrap = await wrapKekWithRecoveryKey(newRawKek, nextRecoveryKey)
      const nextSigning = await generateRecoverySigningMaterial(nextRecoveryKey)
      setPendingRecovery({
        recovery_token: verified.recovery_token,
        new_auth_key: newAuthKey,
        new_salt_auth: newSaltAuth,
        new_salt_crypto: newSaltCrypto,
        new_recovery_wrapped_kek: nextWrap.recovery_wrapped_kek,
        new_recovery_nonce: nextWrap.recovery_nonce,
        new_recovery_public_key: nextSigning.recovery_public_key,
        new_recovery_wrapped_signing_key: nextSigning.recovery_wrapped_signing_key,
        new_recovery_signing_nonce: nextSigning.recovery_signing_nonce,
        entries,
      })
      setNewRecoveryDisplay(recoveryKeyToDisplay(nextRecoveryKey))
      setNewRecoveryConfirm('')
      setStage('recovery-confirm')
    } catch (err: any) {
      setError(err.message || 'Não foi possível recuperar o cofre')
    } finally {
      setLoading(false)
    }
  }
  async function confirmRecovery(ev: FormEvent) {
    ev.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (!pendingRecovery || newRecoveryDisplay !== newRecoveryConfirm) {
        throw new Error('Digite novamente a nova recovery key exatamente como exibida')
      }
      await api.recoveryRecover(pendingRecovery.recovery_token, pendingRecovery)
      setInfo('Recovery concluído. A chave antiga deixou de ser válida.')
      nav('/login')
    } catch (err: any) {
      setError(err.message || 'Não foi possível concluir a recuperação')
    } finally {
      setLoading(false)
    }
  }

  async function requestDestructiveReset(ev: FormEvent) {
    ev.preventDefault()
    setError('')
    if (ack !== email || !email || totpCode.length !== 6) {
      setError('Confirme o e-mail exatamente e informe o código TOTP atual.')
      return
    }
    setLoading(true)
    try {
      const result = await api.passwordResetRequest(email, totpCode)
      if (!result.token) {
        setInfo('Se o pedido for elegível, o link de redefinição será disponibilizado pelo canal configurado.')
        return
      }
      setResetToken(result.token)
      await api.passwordResetValidate(result.token)
      setStage('reset-confirm')
      setInfo('Link de reset validado. O próximo passo apagará o cofre atual.')
    } catch (err: any) {
      setError(err.message || 'Não foi possível iniciar o reset')
    } finally {
      setLoading(false)
    }
  }

  async function confirmDestructiveReset(ev: FormEvent) {
    ev.preventDefault()
    setError('')
    if (!passwordIsValid(newPassword)) return
    setLoading(true)
    try {
      const newSaltAuth = randomSaltB64()
      const newSaltCrypto = randomSaltB64()
      const newAuthKey = await deriveAuthKey(newPassword, newSaltAuth)
      await api.passwordResetConfirm(resetToken, {
        new_auth_key: newAuthKey,
        new_salt_auth: newSaltAuth,
        new_salt_crypto: newSaltCrypto,
      })
      nav('/login', { state: { reset: true } })
    } catch (err: any) {
      setError(err.message || 'Não foi possível concluir o reset')
    } finally {
      setLoading(false)
    }
  }

  const title = stage === 'recovery-confirm'
    ? 'Nova recovery key'
    : stage === 'reset-confirm'
      ? 'Redefinir acesso'
      : 'Recuperar acesso'
  return (
    <div className="min-h-screen flex items-center justify-center px-4">
      <div className="w-full max-w-lg">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-semibold tracking-tight text-stone-900">{title}</h1>
          <p className="text-sm text-stone-500 mt-1">{info || 'Escolha uma forma de recuperar o acesso.'}</p>
        </div>

        {stage === 'choice' && (
          <div className="space-y-3">
            <button
              type="button"
              onClick={chooseRecovery}
              className="w-full text-left p-4 rounded-lg border border-stone-300 hover:bg-stone-50 transition"
            >
              <strong className="block text-sm text-stone-900">Tenho minha recovery key</strong>
              <span className="text-xs text-stone-500">Preserva todas as entradas do cofre.</span>
            </button>
            <button
              type="button"
              onClick={chooseReset}
              className="w-full text-left p-4 rounded-lg border border-red-200 hover:bg-red-50 transition"
            >
              <strong className="block text-sm text-red-800">Não tenho a recovery key</strong>
              <span className="text-xs text-red-700">Reset destrutivo: o cofre atual será apagado.</span>
            </button>
          </div>
        )}

        {stage === 'recovery-key' && (
          <form onSubmit={submitRecoveryKey} className="space-y-4">
            <Field label="E-mail">
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
                placeholder="voce@exemplo.com"
              />
            </Field>
            <Field label="Recovery key">
              <textarea
                required
                value={recoveryKey}
                onChange={(e) => setRecoveryKey(e.target.value)}
                rows={3}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent font-mono text-sm"
                placeholder="XXXX XXXX XXXX ..."
                autoComplete="off"
              />
            </Field>
            <Submit loading={loading}>Continuar</Submit>
          </form>
        )}

        {stage === 'recovery-password' && (
          <form onSubmit={submitRecoveryPassword} className="space-y-4">
            <p className="text-sm text-stone-500 bg-stone-50 border border-stone-200 rounded-md px-3 py-2">
              Recovery Key validada. Nenhum código TOTP é necessário para esta recuperação.
            </p>
            <Field label="Nova senha-mestra">
              <input
                type="password"
                required
                minLength={12}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
              />
            </Field>
            <Field label="Confirmar nova senha-mestra">
              <input
                type="password"
                required
                value={newPasswordConfirm}
                onChange={(e) => setNewPasswordConfirm(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
              />
            </Field>
            <Submit loading={loading}>Reorganizar chaves do cofre</Submit>
          </form>
        )}

        {stage === 'recovery-confirm' && (
          <form onSubmit={confirmRecovery} className="space-y-4">
            <div className="rounded-md border border-amber-200 bg-amber-50 p-4">
              <p className="text-sm font-medium text-amber-900">Salve a nova recovery key antes de continuar.</p>
              <p className="font-mono text-sm mt-2 break-words select-all">{newRecoveryDisplay}</p>
            </div>
            <Field label="Digite a nova recovery key novamente">
              <input
                type="text"
                required
                value={newRecoveryConfirm}
                onChange={(e) => setNewRecoveryConfirm(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent font-mono text-sm"
                autoComplete="off"
              />
            </Field>
            <Submit loading={loading}>Concluir recuperação</Submit>
          </form>
        )}
        {stage === 'reset-request' && (
          <form onSubmit={requestDestructiveReset} className="space-y-4">
            <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-900">
              <strong>ATENÇÃO:</strong> este fluxo apagará permanentemente todas as entradas do cofre.
              Ele não recupera a senha antiga.
            </div>
            <Field label="E-mail">
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
                placeholder="voce@exemplo.com"
              />
            </Field>
            <Field label="Código TOTP atual">
              <input
                type="text"
                inputMode="numeric"
                maxLength={6}
                required
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent text-center tracking-widest"
                placeholder="000000"
              />
            </Field>
            <Field label="Digite seu e-mail novamente para confirmar">
              <input
                type="email"
                required
                value={ack}
                onChange={(e) => setAck(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
                placeholder="voce@exemplo.com"
              />
            </Field>
            <Submit loading={loading}>Enviar pedido de reset destrutivo</Submit>
          </form>
        )}

        {stage === 'reset-confirm' && (
          <form onSubmit={confirmDestructiveReset} className="space-y-4">
            <div className="rounded-md border border-red-200 bg-red-50 p-4 text-sm text-red-900">
              O token foi validado. Ao confirmar, as entradas e o MFA atuais serão apagados.
              Depois será necessário configurar recovery key + TOTP novamente.
            </div>
            <Field label="Nova senha-mestra">
              <input
                type="password"
                required
                minLength={12}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
              />
            </Field>
            <Field label="Confirmar nova senha-mestra">
              <input
                type="password"
                required
                value={newPasswordConfirm}
                onChange={(e) => setNewPasswordConfirm(e.target.value)}
                className="w-full mt-1.5 px-3 py-2 rounded-md border border-stone-300 bg-white text-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900 focus:border-transparent"
              />
            </Field>
            <Submit loading={loading}>Apagar cofre e redefinir acesso</Submit>
          </form>
        )}

        {error && (
          <p className="mt-4 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md px-3 py-2">
            {error}
          </p>
        )}
        {stage === 'choice' || stage === 'recovery-key' || stage === 'reset-request' ? null : null}

        <p className="text-sm text-stone-500 text-center mt-6">
          <Link to="/login" className="font-medium text-stone-900 hover:underline">← Voltar para login</Link>
        </p>
      </div>
    </div>
  )
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block text-sm font-medium text-stone-700">
      {label}
      {children}
    </label>
  )
}

function Submit({ loading, children }: { loading: boolean; children: ReactNode }) {
  return (
    <button
      type="submit"
      disabled={loading}
      className="w-full py-2.5 px-4 rounded-md bg-stone-900 text-white text-sm font-medium hover:bg-stone-800 disabled:opacity-50 transition"
    >
      {loading ? 'Processando…' : children}
    </button>
  )
}
