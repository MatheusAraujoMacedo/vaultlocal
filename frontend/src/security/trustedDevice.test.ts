import { beforeEach, describe, expect, it } from 'vitest'
import {
  clearTrustedDeviceHint,
  getTrustedDeviceHint,
  saveTrustedDeviceHint,
} from './trustedDevice'

function createStorage() {
  const values = new Map<string, string>()
  return {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
    removeItem: (key: string) => values.delete(key),
  }
}

beforeEach(() => {
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: createStorage(),
  })
})

describe('trusted device hint', () => {
  it('round-trips the non-secret device reference', () => {
    saveTrustedDeviceHint({
      email: 'user@example.com',
      credentialId: 'credential-123',
    })

    expect(getTrustedDeviceHint()).toEqual({
      email: 'user@example.com',
      credentialId: 'credential-123',
    })
  })

  it('does not save incomplete hints', () => {
    saveTrustedDeviceHint({ email: '', credentialId: 'credential-123' })
    expect(getTrustedDeviceHint()).toBeNull()

    saveTrustedDeviceHint({ email: 'user@example.com', credentialId: '' })
    expect(getTrustedDeviceHint()).toBeNull()
  })

  it('ignores malformed stored values', () => {
    localStorage.setItem('vaultlocal_trusted_device_v1', '{"email":42}')
    expect(getTrustedDeviceHint()).toBeNull()
  })

  it('clears the hint', () => {
    saveTrustedDeviceHint({
      email: 'user@example.com',
      credentialId: 'credential-123',
    })

    clearTrustedDeviceHint()

    expect(getTrustedDeviceHint()).toBeNull()
  })
})
