import { argon2id } from 'hash-wasm'

function b64encode(bytes: Uint8Array | ArrayBufferLike): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let binary = ''
  for (const b of view) binary += String.fromCharCode(b)
  return btoa(binary)
}

function b64decode(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function ensureArrayBuffer(arr: Uint8Array | ArrayBufferLike): Uint8Array {
  if (arr instanceof Uint8Array) {
    // Create a copy with a plain ArrayBuffer to ensure compatibility
    const plain = new Uint8Array(arr.length)
    plain.set(arr)
    return plain
  }
  return new Uint8Array(arr)
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16)
  }
  return bytes
}

async function deriveRawKey(password: string, saltB64: string): Promise<Uint8Array> {
  const salt = ensureArrayBuffer(b64decode(saltB64))
  const hex = await argon2id({
    password,
    salt,
    parallelism: 2,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'hex',
  })
  return hexToBytes(hex)
}

export function generateSecurePassword(length = 20, useSymbols = true): string {
  if (!Number.isInteger(length) || length < 8 || length > 128) {
    throw new Error('password length must be between 8 and 128 characters')
  }

  let alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
  if (useSymbols) alphabet += '!@#$%^&*()-_=+[]{};:,.<>?'

  const result: string[] = []
  const limit = Math.floor(256 / alphabet.length) * alphabet.length
  const bytes = new Uint8Array(64)

  while (result.length < length) {
    crypto.getRandomValues(bytes)
    for (const byte of bytes) {
      if (byte >= limit) continue
      result.push(alphabet[byte % alphabet.length])
      if (result.length === length) break
    }
  }

  return result.join('')
}

export function randomSaltB64(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return b64encode(bytes)
}

export async function deriveAuthKey(password: string, saltAuthB64: string): Promise<string> {
  const raw = await deriveRawKey(password, saltAuthB64)
  return b64encode(raw)
}

function aadBytes(aad?: string): Uint8Array | undefined {
  return aad === undefined ? undefined : new TextEncoder().encode(aad)
}

export function buildDataKeyAad(entryId: string): string {
  return JSON.stringify(['VaultLocal', 'v2', 'data-key', entryId])
}

export function buildFieldAad(
  entryId: string,
  title: string,
  site: string | null | undefined,
  field: 'username' | 'password' | 'notes',
): string {
  return JSON.stringify(['VaultLocal', 'v2', 'field', entryId, title, site ?? '', field])
}

async function importAesKey(raw: Uint8Array | ArrayBufferLike, extractable = false): Promise<CryptoKey> {
  const arr = ensureArrayBuffer(raw instanceof Uint8Array ? raw : new Uint8Array(raw))
  return crypto.subtle.importKey('raw', arr as BufferSource, 'AES-GCM', extractable, ['encrypt', 'decrypt'])
}

export async function deriveKek(password: string, saltCryptoB64: string): Promise<CryptoKey> {
  const raw = await deriveRawKey(password, saltCryptoB64)
  // KEK nunca precisa ser exportada — fica so em memoria como handle
  return importAesKey(raw, false)
}

let sessionKek: CryptoKey | null = null
let sessionRawKek: Uint8Array | null = null

export function setSessionKek(kek: CryptoKey): void {
  sessionKek = kek
}

export function setSessionRawKek(rawKek: Uint8Array): void {
  if (rawKek.byteLength !== 32) throw new Error('invalid session KEK')
  sessionRawKek?.fill(0)
  sessionRawKek = new Uint8Array(rawKek)
}

export function getSessionRawKek(): Uint8Array {
  if (!sessionRawKek) throw new Error('vault locked, login again')
  return new Uint8Array(sessionRawKek)
}

export function clearSessionKek(): void {
  sessionKek = null
  sessionRawKek?.fill(0)
  sessionRawKek = null
}

export function getSessionKek(): CryptoKey {
  if (!sessionKek) throw new Error('vault locked, login again')
  return sessionKek
}

export interface WrappedKey {
  wrapped_data_key: string
  wrapped_nonce: string
}

export async function generateDataKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
}

export async function wrapDataKey(dataKey: CryptoKey, kek: CryptoKey, aad?: string): Promise<WrappedKey> {
  const raw = ensureArrayBuffer(await crypto.subtle.exportKey('raw', dataKey))
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ciphertext = ensureArrayBuffer(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aadBytes(aad) as BufferSource | undefined },
      kek,
      raw as BufferSource,
    ),
  )
  return { wrapped_data_key: b64encode(ciphertext), wrapped_nonce: b64encode(nonce) }
}

export async function unwrapDataKey(wrapped: WrappedKey, kek: CryptoKey, aad?: string): Promise<CryptoKey> {
  const ciphertext = b64decode(wrapped.wrapped_data_key)
  const nonce = b64decode(wrapped.wrapped_nonce)
  const raw = ensureArrayBuffer(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aadBytes(aad) as BufferSource | undefined },
      kek,
      ciphertext as BufferSource,
    ),
  )
  // data_keys precisam ser extractable porque depois sao wrapped novamente ao salvar
  return importAesKey(raw, true)
}

export interface EncField {
  ciphertext: string
  nonce: string
}

export async function encryptField(plaintext: string, dataKey: CryptoKey, aad?: string): Promise<EncField> {
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const encoded = new TextEncoder().encode(plaintext)
  const ciphertext = ensureArrayBuffer(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aadBytes(aad) as BufferSource | undefined },
      dataKey,
      encoded as BufferSource,
    ),
  )
  return { ciphertext: b64encode(ciphertext), nonce: b64encode(nonce) }
}

export async function decryptField(field: EncField, dataKey: CryptoKey, aad?: string): Promise<string> {
  const ciphertext = b64decode(field.ciphertext)
  const nonce = b64decode(field.nonce)
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource, additionalData: aadBytes(aad) as BufferSource | undefined },
    dataKey,
    ciphertext as BufferSource,
  )
  return new TextDecoder().decode(plaintext)
}

const COMMON_PASSWORDS = new Set([
  '123456', '123456789', '12345678', '1234567', '12345', '1234567890',
  '1234', '123123', '123321', '111111', '000000', '666666', '121212',
  '112233', '654321', '222222', '777777', '888888', '999999',
  'password', 'password1', 'password123', 'passw0rd', 'p@ssw0rd',
  'iloveyou', 'princess', 'sunshine', 'shadow', 'monkey', 'monkey1',
  'dragon', 'master', 'master1', 'letmein', 'login', 'admin',
  'administrator', 'welcome', 'welcome1', 'qwerty', 'qwerty123',
  'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'abc123', 'abcd1234',
  'trustno1', 'starwars', 'superman', 'batman', 'spiderman',
  'football', 'baseball', 'basketball', 'soccer', 'hockey',
  'whatever', 'freedom', 'ninja', 'mustang', 'michael', 'jennifer',
  'jordan23', 'hunter2', 'access', 'flower', 'hottie', 'loveme',
  'charlie', 'donald', 'andrew', 'daniel', 'matthew', 'joshua',
  'george', 'thomas', 'robert', 'buster', 'harley', 'ranger',
  'tigger', 'soccer1', 'cheese', 'summer', 'winter', 'autumn',
  '1q2w3e4r', '1qaz2wsx', 'qazwsx', 'zaq12wsx', 'q1w2e3r4',
  'rockyou', 'changeme', 'letmein1', 'iloveyou1', 'senha',
  'senha123', 'brasil', 'brasil123', 'vasco', 'flamengo', 'corinthians',
  'palmeiras', 'internacional', 'gremio', '12345678910',
  'aaaaaa', 'bbbbbb', '111222', 'asdf1234', 'test1234', 'temp1234',
])

const KEYBOARD_ROWS = ['1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm']

function isSequential(lowered: string): boolean {
  if (lowered.length < 6) return false
  let ascending = true
  let descending = true
  for (let i = 0; i < lowered.length - 1; i++) {
    const diff = lowered.charCodeAt(i + 1) - lowered.charCodeAt(i)
    if (diff !== 1) ascending = false
    if (diff !== -1) descending = false
  }
  return ascending || descending
}

function isSingleCharacter(lowered: string): boolean {
  return new Set(lowered).size === 1
}

function isKeyboardWalk(lowered: string): boolean {
  if (lowered.length < 6) return false
  return KEYBOARD_ROWS.some(
    (row) => row.includes(lowered) || row.split('').reverse().join('').includes(lowered),
  )
}

export function isCommonPassword(password: string): boolean {
  const lowered = password.trim().toLowerCase()
  return (
    COMMON_PASSWORDS.has(lowered) ||
    isSingleCharacter(lowered) ||
    isSequential(lowered) ||
    isKeyboardWalk(lowered)
  )
}


export async function deriveRawKek(password: string, saltCryptoB64: string): Promise<Uint8Array> {
  return deriveRawKey(password, saltCryptoB64)
}


export async function rawKekToCryptoKey(rawKek: Uint8Array): Promise<CryptoKey> {
  if (rawKek.byteLength !== 32) throw new Error('invalid KEK')
  return importAesKey(rawKek, false)
}


export function generateRecoveryKey(): Uint8Array {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return bytes
}


export function recoveryKeyToDisplay(bytes: Uint8Array): string {
  if (bytes.byteLength !== 32) throw new Error('recovery key must be 32 bytes')
  return b64encode(bytes).match(/.{1,4}/g)!.join(' ')
}


export function recoveryKeyFromDisplay(display: string): Uint8Array {
  const normalized = display.replace(/\s/g, '')
  const bytes = b64decode(normalized)
  if (bytes.byteLength !== 32) throw new Error('recovery key inválida')
  return bytes
}


export interface RecoverySigningMaterial {
  recovery_public_key: string
  recovery_wrapped_signing_key: string
  recovery_signing_nonce: string
}


export async function generateRecoverySigningMaterial(
  recoveryKey: Uint8Array,
): Promise<RecoverySigningMaterial> {
  if (recoveryKey.byteLength !== 32) throw new Error('recovery key inválida')
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify'],
  ) as CryptoKeyPair
  const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const privatePkcs8 = ensureArrayBuffer(await crypto.subtle.exportKey('pkcs8', pair.privateKey))
  const recoveryAesKey = await importAesKey(recoveryKey, false)
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ciphertext = ensureArrayBuffer(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce as BufferSource },
    recoveryAesKey,
    privatePkcs8 as BufferSource,
  ))
  return {
    recovery_public_key: JSON.stringify(publicJwk),
    recovery_wrapped_signing_key: b64encode(ciphertext),
    recovery_signing_nonce: b64encode(nonce),
  }
}


export async function recoveryProof(
  recoveryKey: Uint8Array,
  wrappedSigningKeyB64: string,
  signingNonceB64: string,
  challengeB64: string,
): Promise<string> {
  if (recoveryKey.byteLength !== 32) throw new Error('recovery key inválida')
  const challenge = b64decode(challengeB64)
  if (challenge.byteLength !== 32) throw new Error('recovery challenge inválido')
  const recoveryAesKey = await importAesKey(recoveryKey, false)
  const privatePkcs8 = ensureArrayBuffer(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(signingNonceB64) as BufferSource },
    recoveryAesKey,
    b64decode(wrappedSigningKeyB64) as BufferSource,
  ))
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    privatePkcs8 as BufferSource,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  )
  const signature = ensureArrayBuffer(await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    privateKey,
    challenge as BufferSource,
  ))
  if (signature.byteLength !== 64) throw new Error('assinatura de recovery inválida')
  return b64encode(signature)
}


export interface RecoveryWrap {
  recovery_wrapped_kek: string
  recovery_nonce: string
}


export async function wrapKekWithRecoveryKey(
  rawKek: Uint8Array,
  recoveryKey: Uint8Array,
): Promise<RecoveryWrap> {
  if (rawKek.byteLength !== 32 || recoveryKey.byteLength !== 32) {
    throw new Error('invalid recovery material')
  }
  const recoveryAesKey = await importAesKey(recoveryKey, false)
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ciphertext = ensureArrayBuffer(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      recoveryAesKey,
      rawKek as BufferSource,
    ),
  )
  return { recovery_wrapped_kek: b64encode(ciphertext), recovery_nonce: b64encode(nonce) }
}


export async function unwrapKekWithRecoveryKey(
  wrapped: RecoveryWrap,
  recoveryKey: Uint8Array,
): Promise<Uint8Array> {
  if (recoveryKey.byteLength !== 32) throw new Error('recovery key inválida')
  const recoveryAesKey = await importAesKey(recoveryKey, false)
  const ciphertext = b64decode(wrapped.recovery_wrapped_kek)
  const nonce = b64decode(wrapped.recovery_nonce)
  const rawKek = ensureArrayBuffer(
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce as BufferSource },
      recoveryAesKey,
      ciphertext as BufferSource,
    ),
  )
  if (rawKek.byteLength !== 32) throw new Error('recovery envelope inválido')
  return rawKek
}
