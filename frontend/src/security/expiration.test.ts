import { describe, expect, it } from 'vitest'
import { expirationDays, getExpirationState, sortExpirations } from './expiration'

const DAY = 24 * 60 * 60 * 1000
const NOW = Date.parse('2026-09-29T12:00:00.000Z')

function at(days: number): string {
  return new Date(NOW + days * DAY).toISOString()
}

describe('expiration helpers', () => {
  it('classifies expired and upcoming secrets', () => {
    expect(getExpirationState(at(-1), NOW)).toBe('expired')
    expect(getExpirationState(at(7), NOW)).toBe('urgent')
    expect(getExpirationState(at(15), NOW)).toBe('soon')
    expect(getExpirationState(at(30), NOW)).toBe('scheduled')
  })

  it('calculates remaining days with a ceiling', () => {
    expect(expirationDays(at(2.1), NOW)).toBe(3)
    expect(expirationDays(at(-0.1), NOW)).toBe(0)
  })

  it('sorts by operational urgency before date', () => {
    const items = [
      { id: '3', title: 'Later', site: null, expires_at: at(30) },
      { id: '1', title: 'Expired', site: null, expires_at: at(-2) },
      { id: '4', title: 'Soon', site: null, expires_at: at(12) },
      { id: '2', title: 'Urgent', site: null, expires_at: at(3) },
    ]
    expect(sortExpirations(items, NOW).map((item) => item.id)).toEqual(['1', '2', '4', '3'])
  })
})
