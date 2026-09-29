export const DEFAULT_AUTO_LOCK_MS = 5 * 60 * 1000

type LockCallback = () => void

export function createAutoLock(
  onLock: LockCallback,
  timeoutMs = DEFAULT_AUTO_LOCK_MS,
  now: () => number = () => Date.now(),
) {
  let lastActivity = now()
  let timer: ReturnType<typeof setTimeout> | null = null
  let started = false
  let locked = false

  const clearTimer = () => {
    if (timer !== null) {
      clearTimeout(timer)
      timer = null
    }
  }

  const lockIfExpired = () => {
    timer = null
    if (!started || locked) return
    const elapsed = now() - lastActivity
    if (elapsed >= timeoutMs) {
      locked = true
      onLock()
      return
    }
    timer = setTimeout(lockIfExpired, Math.max(250, timeoutMs - elapsed))
  }

  const schedule = () => {
    clearTimer()
    if (!started || locked) return
    timer = setTimeout(lockIfExpired, timeoutMs)
  }

  const activity = () => {
    if (!started || locked) return
    lastActivity = now()
    schedule()
  }

  const visibilityCheck = () => {
    if (!started || locked) return
    if (!document.hidden) lockIfExpired()
  }
  const start = () => {
    if (started) return
    started = true
    lastActivity = now()
    window.addEventListener('keydown', activity)
    window.addEventListener('pointerdown', activity)
    window.addEventListener('touchstart', activity)
    window.addEventListener('scroll', activity, { passive: true })
    document.addEventListener('visibilitychange', visibilityCheck)
    schedule()
  }

  const stop = () => {
    started = false
    clearTimer()
    window.removeEventListener('keydown', activity)
    window.removeEventListener('pointerdown', activity)
    window.removeEventListener('touchstart', activity)
    window.removeEventListener('scroll', activity)
    document.removeEventListener('visibilitychange', visibilityCheck)
  }

  const reset = () => {
    locked = false
    lastActivity = now()
    schedule()
  }

  return {
    activity,
    start,
    stop,
    reset,
    getLastActivity: () => lastActivity,
  }
}
