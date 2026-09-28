import { describe, expect, it } from 'vitest'
import {
  decryptKekWithPrf,
  encryptKekWithPrf,
} from './webauthn'

function random32(): Uint8Array {
  const value = new Uint8Array(32)
  crypto.getRandomValues(value)
  return value
}

describe('WebAuthn PRF KEK envelope', () => {
  it('round-trips the raw KEK with the same PRF and credential', async () => {
    const rawKek = random32()
    const prf = random32()
    const credentialId = 'credential-test'

    const envelope = await encryptKekWithPrf(rawKek, prf, credentialId)
    const recovered = await decryptKekWithPrf(
      envelope.encrypted_kek,
      envelope.kek_nonce,
      prf,
      credentialId,
    )

    expect(Array.from(recovered)).toEqual(Array.from(rawKek))
  })

  it('rejects the envelope with a different credential binding', async () => {
    const rawKek = random32()
    const prf = random32()
    const envelope = await encryptKekWithPrf(rawKek, prf, 'credential-a')

    await expect(
      decryptKekWithPrf(
        envelope.encrypted_kek,
        envelope.kek_nonce,
        prf,
        'credential-b',
      ),
    ).rejects.toThrow()
  })

  it('rejects the envelope with a different PRF output', async () => {
    const rawKek = random32()
    const prf = random32()
    const envelope = await encryptKekWithPrf(rawKek, prf, 'credential-a')

    await expect(
      decryptKekWithPrf(
        envelope.encrypted_kek,
        envelope.kek_nonce,
        random32(),
        'credential-a',
      ),
    ).rejects.toThrow()
  })
})
