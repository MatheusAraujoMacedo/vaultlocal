type BinaryLike = ArrayBuffer | ArrayBufferView

function base64ToBytes(value: string): Uint8Array {
  const normalized = value.includes('-') || value.includes('_')
    ? value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4)
    : value
  const binary = atob(normalized)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function bytesToBase64(value: BinaryLike): string {
  const bytes = value instanceof ArrayBuffer
    ? new Uint8Array(value)
    : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function bytesToBase64Url(value: BinaryLike): string {
  return bytesToBase64(value)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function base64UrlToBytes(value: string): Uint8Array {
  return base64ToBytes(value)
}

function toArrayBuffer(value: string): ArrayBuffer {
  const bytes = base64UrlToBytes(value)
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer
}

function bufferToArrayBuffer(value: ArrayBuffer | ArrayBufferView): ArrayBuffer {
  if (value instanceof ArrayBuffer) return value
  return value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength) as ArrayBuffer
}

function normalizeCreationOptions(raw: any): PublicKeyCredentialCreationOptions {
  return {
    ...raw,
    challenge: toArrayBuffer(raw.challenge),
    user: {
      ...raw.user,
      id: toArrayBuffer(raw.user.id),
    },
    excludeCredentials: raw.excludeCredentials?.map((item: any) => ({
      ...item,
      id: toArrayBuffer(item.id),
    })),
  }
}

function normalizeRequestOptions(
  raw: any,
  prfSalts: Record<string, string>,
): PublicKeyCredentialRequestOptions {
  const allowCredentials = (raw.allowCredentials ?? []).map((item: any) => ({
    ...item,
    id: toArrayBuffer(item.id),
  }))
  const evalByCredential: Record<string, { first: ArrayBuffer }> = {}
  for (const item of raw.allowCredentials ?? []) {
    const salt = prfSalts[item.id]
    if (!salt) continue
    const bytes = base64ToBytes(salt)
    evalByCredential[item.id] = {
      first: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer,
    }
  }
  return {
    ...raw,
    challenge: toArrayBuffer(raw.challenge),
    allowCredentials,
    extensions: {
      ...(raw.extensions ?? {}),
      prf: { evalByCredential },
    },
  }
}

function serializedCredential(credential: PublicKeyCredential): Record<string, unknown> {
  const withJson = credential as PublicKeyCredential & { toJSON?: () => Record<string, unknown> }
  if (typeof withJson.toJSON === 'function') return withJson.toJSON()
  const response = credential.response as AuthenticatorResponse & {
    authenticatorData?: ArrayBuffer
    clientDataJSON: ArrayBuffer
    signature?: ArrayBuffer
    attestationObject?: ArrayBuffer
    userHandle?: ArrayBuffer | null
  }
  return {
    id: credential.id,
    rawId: bytesToBase64Url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bytesToBase64Url(response.clientDataJSON),
      ...(response.attestationObject
        ? { attestationObject: bytesToBase64Url(response.attestationObject) }
        : {}),
      ...(response.authenticatorData
        ? { authenticatorData: bytesToBase64Url(response.authenticatorData) }
        : {}),
      ...(response.signature
        ? { signature: bytesToBase64Url(response.signature) }
        : {}),
      ...(response.userHandle
        ? { userHandle: bytesToBase64Url(response.userHandle) }
        : {}),
    },
  }
}

export function webauthnAvailable(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential &&
    !!navigator.credentials
}

export async function registerPasskey(options: any): Promise<Record<string, unknown>> {
  if (!webauthnAvailable()) throw new Error('WebAuthn não está disponível neste navegador')
  const credential = await navigator.credentials.create({
    publicKey: normalizeCreationOptions(options),
  })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('Não foi possível criar a passkey')
  return serializedCredential(credential)
}

export async function authenticatePasskey(
  options: any,
  prfSalts: Record<string, string>,
): Promise<{ credential: Record<string, unknown>; credentialId: string; prfOutput: Uint8Array }> {
  if (!webauthnAvailable()) throw new Error('WebAuthn não está disponível neste navegador')
  if (!Object.keys(prfSalts).length) throw new Error('Nenhuma passkey confiável disponível')
  const credential = await navigator.credentials.get({
    publicKey: normalizeRequestOptions(options, prfSalts),
  })
  if (!(credential instanceof PublicKeyCredential)) throw new Error('Não foi possível autenticar com a passkey')
  const extensions = credential.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer | ArrayBufferView } }
  }
  const first = extensions.prf?.results?.first
  if (!first) {
    throw new Error('Esta passkey não oferece PRF; use a senha-mestra para entrar')
  }
  return {
    credential: serializedCredential(credential),
    credentialId: bytesToBase64Url(credential.rawId),
    prfOutput: new Uint8Array(bufferToArrayBuffer(first)),
  }
}

export async function getPrfForCredential(
  credentialId: string,
  prfSalt: string,
): Promise<Uint8Array> {
  if (!webauthnAvailable()) throw new Error('WebAuthn não está disponível neste navegador')
  const challenge = new Uint8Array(32)
  crypto.getRandomValues(challenge)
  const options = {
    challenge: bytesToBase64Url(challenge),
    timeout: 60000,
    rpId: window.location.hostname,
    userVerification: 'required',
    allowCredentials: [{ id: credentialId, type: 'public-key' }],
  }
  const result = await authenticatePasskey(options, { [credentialId]: prfSalt })
  return result.prfOutput
}

async function deriveDeviceKey(prfOutput: Uint8Array, credentialId: string): Promise<CryptoKey> {
  if (prfOutput.byteLength !== 32) throw new Error('PRF inválido')
  const owned = new Uint8Array(new ArrayBuffer(prfOutput.byteLength))
  owned.set(prfOutput)
  const material = await crypto.subtle.importKey(
    'raw',
    owned.buffer,
    'HKDF',
    false,
    ['deriveKey'],
  )
  const salt = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode('VaultLocal-WebAuthn-PRF-v1'),
  )
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info: new TextEncoder().encode(`kek:${credentialId}`),
    },
    material,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  )
}

function deviceKekAad(credentialId: string): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify(['VaultLocal', 'v1', 'device-kek', credentialId]),
  )
}

export async function encryptKekWithPrf(
  rawKek: Uint8Array,
  prfOutput: Uint8Array,
  credentialId: string,
): Promise<{ encrypted_kek: string; kek_nonce: string }> {
  if (rawKek.byteLength !== 32) throw new Error('KEK inválida')
  const key = await deriveDeviceKey(prfOutput, credentialId)
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: bufferToArrayBuffer(nonce),
      additionalData: bufferToArrayBuffer(deviceKekAad(credentialId)),
    },
    key,
    bufferToArrayBuffer(rawKek),
  )
  return {
    encrypted_kek: bytesToBase64(ciphertext),
    kek_nonce: bytesToBase64(nonce),
  }
}

export async function decryptKekWithPrf(
  encryptedKek: string,
  kekNonce: string,
  prfOutput: Uint8Array,
  credentialId: string,
): Promise<Uint8Array> {
  const key = await deriveDeviceKey(prfOutput, credentialId)
  const rawKek = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: bufferToArrayBuffer(base64ToBytes(kekNonce)),
      additionalData: bufferToArrayBuffer(deviceKekAad(credentialId)),
    },
    key,
    bufferToArrayBuffer(base64ToBytes(encryptedKek)),
  )
  const result = new Uint8Array(rawKek)
  if (result.byteLength !== 32) throw new Error('envelope da KEK inválido')
  return result
}
