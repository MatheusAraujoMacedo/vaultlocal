import { afterEach, describe, expect, it } from 'vitest'
import { api, EntryBlob } from './api'
import {
  buildDataKeyAad,
  buildFieldAad,
  encryptField,
  generateDataKey,
  rawKekToCryptoKey,
  setSessionKek,
  wrapDataKey,
  clearSessionKek,
} from './crypto'
import {
  createEncryptedExport,
  decryptEncryptedExport,
  encryptPortableEntry,
} from './export'

const rawKek = new Uint8Array(32).fill(7)

async function makeEntry(): Promise<EntryBlob> {
  const id = crypto.randomUUID()
  const key = await generateDataKey()
  const kek = await rawKekToCryptoKey(rawKek)
  const wrapped = await wrapDataKey(key, kek, buildDataKeyAad(id))
  const username = await encryptField('usuario@example.com', key, buildFieldAad(id, 'GitHub', 'github.com', 'username'))
  const password = await encryptField('Senha-Export-123!', key, buildFieldAad(id, 'GitHub', 'github.com', 'password'))
  const customFields = await encryptField(
    JSON.stringify([{ name: 'API Key', value: 'secret-api-key' }]),
    key,
    buildFieldAad(id, 'GitHub', 'github.com', 'custom_fields'),
  )
  const history = await encryptField(
    JSON.stringify([{ password: 'Senha-Export-Old!', changed_at: '2029-01-02T03:04:05.000Z' }]),
    key,
    buildFieldAad(id, 'GitHub', 'github.com', 'password_history'),
  )

  return {
    id,
    crypto_version: 2,
    title: 'GitHub',
    site: 'github.com',
    favorite: true,
    tags: 'trabalho,dev',
    expires_at: '2030-01-02T03:04:05.000Z',
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    username_enc: username.ciphertext,
    nonce_username: username.nonce,
    password_enc: password.ciphertext,
    nonce_password: password.nonce,
    password_history_enc: history.ciphertext,
    nonce_password_history: history.nonce,
    custom_fields_enc: customFields.ciphertext,
    nonce_custom_fields: customFields.nonce,
    notes_enc: null,
    nonce_notes: null,
    wrapped_data_key: wrapped.wrapped_data_key,
    wrapped_nonce: wrapped.wrapped_nonce,
  }
}

afterEach(() => {
  clearSessionKek()
})

describe('encrypted export', () => {
  it('round-trips vault content without plaintext in the envelope', async () => {
    setSessionKek(await rawKekToCryptoKey(rawKek))
    const entry = await makeEntry()
    const exported = await createEncryptedExport([entry], 'Export-password-123')
    expect(exported).not.toContain('Senha-Export-123!')
    expect(exported).not.toContain('Senha-Export-Old!')
    expect(exported).not.toContain('secret-api-key')
    expect(exported).not.toContain('usuario@example.com')

    const entries = await decryptEncryptedExport(exported, 'Export-password-123')
    expect(entries).toEqual([{
      title: 'GitHub',
      site: 'github.com',
      username: 'usuario@example.com',
      password: 'Senha-Export-123!',
      notes: null,
      tags: 'trabalho,dev',
      expires_at: '2030-01-02T03:04:05.000Z',
      favorite: true,
      password_history: [{ password: 'Senha-Export-Old!', changed_at: '2029-01-02T03:04:05.000Z' }],
      custom_fields: [{ name: 'API Key', value: 'secret-api-key' }],
    }])
  })

  it('rejects the wrong export password', async () => {
    setSessionKek(await rawKekToCryptoKey(rawKek))
    const entry = await makeEntry()
    const exported = await createEncryptedExport([entry], 'Export-password-123')

    await expect(
      decryptEncryptedExport(exported, 'senha-errada-456'),
    ).rejects.toThrow('Senha de exportação incorreta ou arquivo corrompido')
  })
})
