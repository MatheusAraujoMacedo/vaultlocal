import { describe, expect, it } from 'vitest'
import {
  buildDataKeyAad,
  buildFieldAad,
  decryptField,
  encryptField,
  generateDataKey,
  unwrapDataKey,
  wrapDataKey,
} from './crypto'

describe('authenticated encryption', () => {
  it('decrypts v2 fields only with the matching AAD', async () => {
    const key = await generateDataKey()
    const aad = buildFieldAad('entry-1', 'GitHub', 'github.com', 'password')
    const encrypted = await encryptField('super-secret', key, aad)

    await expect(decryptField(encrypted, key, aad)).resolves.toBe('super-secret')
    await expect(decryptField(encrypted, key, buildFieldAad('entry-1', 'Changed', 'github.com', 'password'))).rejects.toThrow()
    await expect(decryptField(encrypted, key, buildFieldAad('entry-2', 'GitHub', 'github.com', 'password'))).rejects.toThrow()
  })

  it('can still decrypt legacy v1 fields without AAD', async () => {
    const key = await generateDataKey()
    const encrypted = await encryptField('legacy-secret', key)

    await expect(decryptField(encrypted, key)).resolves.toBe('legacy-secret')
  })

  it('binds wrapped data keys to their entry id', async () => {
    const kek = await generateDataKey()
    const dataKey = await generateDataKey()
    const aad = buildDataKeyAad('entry-123')
    const wrapped = await wrapDataKey(dataKey, kek, aad)

    await expect(unwrapDataKey(wrapped, kek, aad)).resolves.toBeInstanceOf(CryptoKey)
    await expect(unwrapDataKey(wrapped, kek, buildDataKeyAad('entry-456'))).rejects.toThrow()
  })
})
