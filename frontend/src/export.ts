import { EntryBlob } from './api'
import {
  buildDataKeyAad,
  buildFieldAad,
  decryptField,
  encryptField,
  generateDataKey,
  getSessionKek,
  randomSaltB64,
  deriveRawKek,
  rawKekToCryptoKey,
  unwrapDataKey,
  wrapDataKey,
} from './crypto'

const EXPORT_MAGIC = 'VaultLocal Export'
const EXPORT_VERSION = 1
const EXPORT_AAD = 'VaultLocal:export:v1'
const MAX_EXPORT_BYTES = 50 * 1024 * 1024
const MAX_ENTRIES = 10_000
const MAX_FIELD_CHARS = 1_000_000

interface PortableEntry {
  title: string
  site: string | null
  username: string
  password: string
  notes: string | null
  tags: string
  expires_at: string | null
}

interface ExportEnvelope {
  magic: typeof EXPORT_MAGIC
  version: typeof EXPORT_VERSION
  kdf: {
    name: 'argon2id'
    salt: string
    iterations: 3
    memory_kib: 65536
    parallelism: 2
  }
  cipher: {
    name: 'AES-256-GCM'
    nonce: string
    aad: typeof EXPORT_AAD
  }
  ciphertext: string
}

function bytesToB64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function b64ToBytes(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}

function validatePortableEntry(entry: unknown): PortableEntry {
  if (!entry || typeof entry !== 'object') throw new Error('Entrada de exportação inválida')
  const value = entry as Record<string, unknown>
  const title = value.title
  const site = value.site
  const username = value.username
  const password = value.password
  const notes = value.notes
  const tags = value.tags
  const expiresAt = value.expires_at ?? null

  if (typeof title !== 'string' || title.length < 1 || title.length > 255) {
    throw new Error('Título inválido no arquivo de exportação')
  }
  if (site !== null && (typeof site !== 'string' || site.length > 255)) {
    throw new Error('Site inválido no arquivo de exportação')
  }
  if (typeof username !== 'string' || username.length > MAX_FIELD_CHARS) {
    throw new Error('Usuário inválido no arquivo de exportação')
  }
  if (typeof password !== 'string' || password.length > MAX_FIELD_CHARS) {
    throw new Error('Senha inválida no arquivo de exportação')
  }
  if (notes !== null && typeof notes !== 'string') throw new Error('Notas inválidas no arquivo de exportação')
  if (typeof notes === 'string' && notes.length > MAX_FIELD_CHARS) {
    throw new Error('Notas excedem o limite permitido')
  }
  if (typeof tags !== 'string' || tags.length > 512) throw new Error('Tags inválidas no arquivo de exportação')
  if (expiresAt !== null && (typeof expiresAt !== 'string' || Number.isNaN(new Date(expiresAt).getTime()))) {
    throw new Error('Data de expiração inválida no arquivo de exportação')
  }

  return { title, site: site as string | null, username, password, notes: notes as string | null, tags, expires_at: expiresAt as string | null }
}

async function deriveExportKey(password: string, salt: string): Promise<CryptoKey> {
  const raw = await deriveRawKek(password, salt)
  return rawKekToCryptoKey(raw)
}

async function decryptEntry(entry: EntryBlob, kek: CryptoKey): Promise<PortableEntry> {
  const key = await unwrapDataKey(
    { wrapped_data_key: entry.wrapped_data_key, wrapped_nonce: entry.wrapped_nonce },
    kek,
    entry.crypto_version === 2 ? buildDataKeyAad(entry.id) : undefined,
  )
  const username = await decryptField(
    { ciphertext: entry.username_enc, nonce: entry.nonce_username },
    key,
    entry.crypto_version === 2
      ? buildFieldAad(entry.id, entry.title, entry.site, 'username')
      : undefined,
  )
  const password = await decryptField(
    { ciphertext: entry.password_enc, nonce: entry.nonce_password },
    key,
    entry.crypto_version === 2
      ? buildFieldAad(entry.id, entry.title, entry.site, 'password')
      : undefined,
  )
  const notes = entry.notes_enc
    ? await decryptField(
        { ciphertext: entry.notes_enc, nonce: entry.nonce_notes! },
        key,
        entry.crypto_version === 2
          ? buildFieldAad(entry.id, entry.title, entry.site, 'notes')
          : undefined,
      )
    : null

  return {
    title: entry.title,
    site: entry.site,
    username,
    password,
    notes,
    tags: entry.tags,
    expires_at: entry.expires_at,
  }
}

export async function createEncryptedExport(entries: EntryBlob[], password: string): Promise<string> {
  if (password.length < 12) throw new Error('A senha da exportação deve ter pelo menos 12 caracteres')
  if (entries.length > MAX_ENTRIES) throw new Error('O cofre excede o limite de exportação')

  const kek = getSessionKek()
  const portableEntries = []
  for (const entry of entries) {
    portableEntries.push(await decryptEntry(entry, kek))
  }

  const payload = new TextEncoder().encode(JSON.stringify({
    created_at: new Date().toISOString(),
    entries: portableEntries,
  }))
  const salt = randomSaltB64()
  const key = await deriveExportKey(password, salt)
  const nonce = new Uint8Array(12)
  crypto.getRandomValues(nonce)
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: new TextEncoder().encode(EXPORT_AAD),
    },
    key,
    payload,
  ))

  const envelope: ExportEnvelope = {
    magic: EXPORT_MAGIC,
    version: EXPORT_VERSION,
    kdf: {
      name: 'argon2id',
      salt,
      iterations: 3,
      memory_kib: 65536,
      parallelism: 2,
    },
    cipher: {
      name: 'AES-256-GCM',
      nonce: bytesToB64(nonce),
      aad: EXPORT_AAD,
    },
    ciphertext: bytesToB64(ciphertext),
  }
  return JSON.stringify(envelope, null, 2)
}

export async function decryptEncryptedExport(
  serialized: string,
  password: string,
): Promise<PortableEntry[]> {
  if (new TextEncoder().encode(serialized).byteLength > MAX_EXPORT_BYTES) {
    throw new Error('Arquivo de exportação excede o limite permitido')
  }

  let envelope: unknown
  try {
    envelope = JSON.parse(serialized)
  } catch {
    throw new Error('Arquivo de exportação inválido')
  }

  if (!envelope || typeof envelope !== 'object') throw new Error('Arquivo de exportação inválido')
  const value = envelope as Record<string, unknown>
  const kdf = value.kdf
  const cipher = value.cipher
  if (
    value.magic !== EXPORT_MAGIC ||
    value.version !== EXPORT_VERSION ||
    !kdf ||
    typeof kdf !== 'object' ||
    !cipher ||
    typeof cipher !== 'object' ||
    typeof value.ciphertext !== 'string'
  ) {
    throw new Error('Formato de exportação não reconhecido')
  }

  const kdfValue = kdf as Record<string, unknown>
  const cipherValue = cipher as Record<string, unknown>
  if (
    kdfValue.name !== 'argon2id' ||
    kdfValue.iterations !== 3 ||
    kdfValue.memory_kib !== 65536 ||
    kdfValue.parallelism !== 2 ||
    typeof kdfValue.salt !== 'string' ||
    cipherValue.name !== 'AES-256-GCM' ||
    cipherValue.aad !== EXPORT_AAD ||
    typeof cipherValue.nonce !== 'string'
  ) {
    throw new Error('Parâmetros criptográficos de exportação inválidos')
  }

  try {
    const nonce = b64ToBytes(cipherValue.nonce)
    if (nonce.byteLength !== 12) throw new Error('invalid nonce')
    const ciphertext = b64ToBytes(value.ciphertext)
    if (ciphertext.byteLength < 16) throw new Error('invalid ciphertext')
    const key = await deriveExportKey(password, kdfValue.salt)
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: nonce as BufferSource,
        additionalData: new TextEncoder().encode(EXPORT_AAD) as BufferSource,
      },
      key,
      ciphertext as BufferSource,
    )
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as { entries?: unknown }
    if (!Array.isArray(parsed.entries) || parsed.entries.length > MAX_ENTRIES) {
      throw new Error('Lista de entradas inválida')
    }
    return parsed.entries.map(validatePortableEntry)
  } catch {
    throw new Error('Senha de exportação incorreta ou arquivo corrompido')
  }
}
export async function encryptPortableEntry(entry: PortableEntry): Promise<{
  id: string
  crypto_version: 2
  title: string
  site: string | null
  username_enc: string
  nonce_username: string
  password_enc: string
  nonce_password: string
  notes_enc: string | null
  nonce_notes: string | null
  wrapped_data_key: string
  wrapped_nonce: string
  tags: string
  expires_at: string | null
}> {
  const kek = getSessionKek()
  const id = crypto.randomUUID()
  const dataKey = await generateDataKey()
  const wrapped = await wrapDataKey(dataKey, kek, buildDataKeyAad(id))
  const username = await encryptField(
    entry.username,
    dataKey,
    buildFieldAad(id, entry.title, entry.site, 'username'),
  )
  const password = await encryptField(
    entry.password,
    dataKey,
    buildFieldAad(id, entry.title, entry.site, 'password'),
  )
  const notes = entry.notes
    ? await encryptField(
        entry.notes,
        dataKey,
        buildFieldAad(id, entry.title, entry.site, 'notes'),
      )
    : null

  return {
    id,
    crypto_version: 2,
    title: entry.title,
    site: entry.site,
    username_enc: username.ciphertext,
    nonce_username: username.nonce,
    password_enc: password.ciphertext,
    nonce_password: password.nonce,
    notes_enc: notes?.ciphertext ?? null,
    nonce_notes: notes?.nonce ?? null,
    wrapped_data_key: wrapped.wrapped_data_key,
    wrapped_nonce: wrapped.wrapped_nonce,
    tags: entry.tags,
    expires_at: entry.expires_at,
  }
}

export type { PortableEntry }
