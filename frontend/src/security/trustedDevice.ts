export interface TrustedDeviceHint {
  email: string
  credentialId: string
}

const STORAGE_KEY = 'vaultlocal_trusted_device_v1'

export function saveTrustedDeviceHint(hint: TrustedDeviceHint): void {
  if (!hint.email || !hint.credentialId) return
  localStorage.setItem(STORAGE_KEY, JSON.stringify(hint))
}

export function getTrustedDeviceHint(): TrustedDeviceHint | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return null
    const parsed = JSON.parse(raw) as Partial<TrustedDeviceHint>
    if (typeof parsed.email !== 'string' || !parsed.email) return null
    if (typeof parsed.credentialId !== 'string' || !parsed.credentialId) return null
    return { email: parsed.email, credentialId: parsed.credentialId }
  } catch {
    return null
  }
}

export function clearTrustedDeviceHint(): void {
  localStorage.removeItem(STORAGE_KEY)
}
