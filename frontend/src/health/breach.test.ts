import { describe, expect, it, vi } from 'vitest';
import { checkPasswordsWithHibp, sha1Hex } from './breach';

describe('sha1Hex', () => {
  it('matches the canonical SHA-1 value for password', async () => {
    await expect(sha1Hex('password')).resolves.toBe(
      '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8',
    );
  });
});

describe('checkPasswordsWithHibp', () => {
  it('sends only hash prefixes and matches suffixes locally', async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe('https://api.pwnedpasswords.com/range/5BAA6');
      expect(init?.headers).toEqual({ 'Add-Padding': 'true' });

      return new Response(
        [
          '1E4C9B93F3F0682250B6CF8331B7EE68FD8:10',
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:0',
        ].join('\r\n'),
        { status: 200 },
      );
    });

    const result = await checkPasswordsWithHibp(
      [{ id: 'entry-1', password: 'password' }],
      fetchMock as unknown as typeof fetch,
    );

    expect(result.checkedEntries).toBe(1);
    expect(result.checkedPrefixes).toBe(1);
    expect(result.matches).toEqual([{ entryId: 'entry-1', prevalence: 10 }]);
  });

  it('deduplicates requests by hash prefix', async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(url).toBe('https://api.pwnedpasswords.com/range/5BAA6');
      return new Response('1E4C9B93F3F0682250B6CF8331B7EE68FD8:3\r\n', { status: 200 });
    });

    const result = await checkPasswordsWithHibp(
      [
        { id: 'entry-1', password: 'password' },
        { id: 'entry-2', password: 'password' },
      ],
      fetchMock as unknown as typeof fetch,
    );

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(result.matches).toEqual([
      { entryId: 'entry-1', prevalence: 3 },
      { entryId: 'entry-2', prevalence: 3 },
    ]);
  });

  it('throws when HIBP is unavailable', async () => {
    const fetchMock = vi.fn(async () => new Response('', { status: 503 }));

    await expect(
      checkPasswordsWithHibp(
        [{ id: 'entry-1', password: 'password' }],
        fetchMock as unknown as typeof fetch,
      ),
    ).rejects.toThrow('HTTP 503');
  });
});
