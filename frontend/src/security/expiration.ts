export type ExpirationState = 'expired' | 'urgent' | 'soon' | 'scheduled'

export interface ExpirationItem {
  id: string
  title: string
  site: string | null
  expires_at: string
}

export function getExpirationState(value: string, now = Date.now()): ExpirationState | null {
  const timestamp = new Date(value).getTime()
  if (Number.isNaN(timestamp)) return null
  const days = Math.ceil((timestamp - now) / (24 * 60 * 60 * 1000))
  if (days <= 0) return 'expired'
  if (days <= 7) return 'urgent'
  if (days <= 15) return 'soon'
  return 'scheduled'
}

export function sortExpirations(items: ExpirationItem[], now = Date.now()): ExpirationItem[] {
  return [...items].sort((a, b) => {
    const aTime = new Date(a.expires_at).getTime()
    const bTime = new Date(b.expires_at).getTime()
    const aInvalid = Number.isNaN(aTime)
    const bInvalid = Number.isNaN(bTime)
    if (aInvalid !== bInvalid) return aInvalid ? 1 : -1
    if (aInvalid && bInvalid) return a.title.localeCompare(b.title)
    const aState = getExpirationState(a.expires_at, now)
    const bState = getExpirationState(b.expires_at, now)
    const rank: Record<ExpirationState, number> = {
      expired: 0,
      urgent: 1,
      soon: 2,
      scheduled: 3,
    }
    if (aState && bState && rank[aState] !== rank[bState]) {
      return rank[aState] - rank[bState]
    }
    return aTime - bTime
  })
}

export function expirationDays(value: string, now = Date.now()): number | null {
  const timestamp = new Date(value).getTime()
  if (Number.isNaN(timestamp)) return null
  const days = Math.ceil((timestamp - now) / (24 * 60 * 60 * 1000))
  return Object.is(days, -0) ? 0 : days
}
