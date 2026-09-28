import { describe, expect, it } from 'vitest'
import {
  buildDataKeyAad,
  generateSecurePassword,
  buildFieldAad,
  decryptField,
  encryptField,
  generateDataKey,
  unwrapDataKey,
  wrapDataKey,
  deriveRawKek,
  generateRecoveryKey,
  generateRecoverySigningMaterial,
  recoveryKeyFromDisplay,
  recoveryKeyToDisplay,
  recoveryProof,
  rawKekToCryptoKey,
  wrapKekWithRecoveryKey,
  unwrapKekWithRecoveryKey,
} from './crypto'

describe('authenticated encryption', () => {
  it('generates a secure password locally with requested length', () => {
    const password = generateSecurePassword(32, true)
    expect(password).toHaveLength(32)
  })

  it('generates alphanumeric-only passwords when symbols are disabled', () => {
    const password = generateSecurePassword(24, false)
    expect(password).toHaveLength(24)
    expect(password).toMatch(/^[A-Za-z0-9]+$/)
  })

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


describe('recovery envelope', () => {
  it('round-trips a KEK through a 32-byte recovery key', async () => {
    const rawKek = await deriveRawKek('Strong test password 123!', btoa('0123456789abcdef'))
    const recoveryKey = generateRecoveryKey()
    const display = recoveryKeyToDisplay(recoveryKey)
    expect(recoveryKeyFromDisplay(display)).toEqual(recoveryKey)

    const wrapped = await wrapKekWithRecoveryKey(rawKek, recoveryKey)
    await expect(unwrapKekWithRecoveryKey(wrapped, recoveryKey)).resolves.toEqual(rawKek)
    const kek = await rawKekToCryptoKey(rawKek)
    expect(kek).toBeInstanceOf(CryptoKey)
  })

  it('rejects an incorrect recovery key locally', async () => {
    const rawKek = new Uint8Array(32).fill(7)
    const recoveryKey = generateRecoveryKey()
    const wrongKey = generateRecoveryKey()
    const wrapped = await wrapKekWithRecoveryKey(rawKek, recoveryKey)
    await expect(unwrapKekWithRecoveryKey(wrapped, wrongKey)).rejects.toThrow()
  })

  it('generates encrypted ECDSA recovery signing material and challenge proof', async () => {
    const recoveryKey = generateRecoveryKey()
    const material = await generateRecoverySigningMaterial(recoveryKey)
    const challengeBytes = new Uint8Array(32).fill(9)
    let binary = ''
    for (const byte of challengeBytes) binary += String.fromCharCode(byte)
    const challenge = btoa(binary)

    const proof = await recoveryProof(
      recoveryKey,
      material.recovery_wrapped_signing_key,
      material.recovery_signing_nonce,
      challenge,
    )

    expect(JSON.parse(material.recovery_public_key).crv).toBe('P-256')
    expect(JSON.parse(material.recovery_public_key).kty).toBe('EC')
    expect(atob(proof)).toHaveLength(64)
    await expect(recoveryProof(
      recoveryKey,
      material.recovery_wrapped_signing_key,
      material.recovery_signing_nonce,
      btoa('different challenge'.padEnd(32, 'x')),
    )).resolves.not.toBe(proof)
  })
})
