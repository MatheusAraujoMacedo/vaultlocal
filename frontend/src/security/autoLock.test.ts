import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createAutoLock } from './autoLock'

beforeEach(() => {
  vi.useRealTimers()
  ;(globalThis as Record<string, unknown>).window = new EventTarget()
  ;(globalThis as Record<string, unknown>).document = Object.assign(
    new EventTarget(),
    { hidden: false },
  )
})

describe('auto lock', () => {
  it('locks after the configured inactivity window', () => {
    vi.useFakeTimers()
    const onLock = vi.fn()
    const lock = createAutoLock(onLock, 5_000)

    lock.start()
    vi.advanceTimersByTime(4_999)
    expect(onLock).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1)
    expect(onLock).toHaveBeenCalledTimes(1)
  })

  it('activity postpones the lock', () => {
    vi.useFakeTimers()
    const onLock = vi.fn()
    const lock = createAutoLock(onLock, 5_000)

    lock.start()
    vi.advanceTimersByTime(4_000)
    window.dispatchEvent(new Event('pointerdown'))
    vi.advanceTimersByTime(4_999)
    expect(onLock).not.toHaveBeenCalled()

    vi.advanceTimersByTime(1)
    expect(onLock).toHaveBeenCalledTimes(1)
  })

  it('does not lock more than once', () => {
    vi.useFakeTimers()
    const onLock = vi.fn()
    const lock = createAutoLock(onLock, 1_000)

    lock.start()
    vi.advanceTimersByTime(3_000)
    expect(onLock).toHaveBeenCalledTimes(1)
  })
})
