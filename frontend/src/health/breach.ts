const HIBP_RANGE_URL = 'https://api.pwnedpasswords.com/range/';
const MAX_CONCURRENT_REQUESTS = 4;
const REQUEST_TIMEOUT_MS = 10_000;

export interface EntryBreachMatch {
  entryId: string;
  prevalence: number;
}

export interface BreachCheckResult {
  matches: EntryBreachMatch[];
  checkedEntries: number;
  checkedPrefixes: number;
}

interface HashedEntry {
  entryId: string;
  fullHash: string;
}

function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/**
 * SHA-1 is used only because HIBP's Pwned Passwords range API indexes SHA-1.
 * The complete password and complete hash never leave the browser.
 */
export async function sha1Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  return toHex(await globalThis.crypto.subtle.digest('SHA-1', bytes));
}

function parseRangeResponse(body: string): Map<string, number> {
  const suffixes = new Map<string, number>();

  for (const line of body.split(/\r?\n/)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;

    const suffix = line.slice(0, separator).trim().toUpperCase();
    const count = Number.parseInt(line.slice(separator + 1).trim(), 10);

    if (/^[0-9A-F]{35}$/.test(suffix) && Number.isFinite(count) && count >= 0) {
      suffixes.set(suffix, count);
    }
  }

  return suffixes;
}

async function queryPrefix(
  prefix: string,
  entries: HashedEntry[],
  fetchImpl: typeof fetch,
): Promise<EntryBreachMatch[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetchImpl(HIBP_RANGE_URL + prefix, {
      method: 'GET',
      headers: {
        'Add-Padding': 'true',
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error('HIBP retornou HTTP ' + response.status);
    }

    const suffixes = parseRangeResponse(await response.text());
    const matches: EntryBreachMatch[] = [];

    for (const entry of entries) {
      const suffix = entry.fullHash.slice(5);
      const prevalence = suffixes.get(suffix);
      if (prevalence !== undefined && prevalence > 0) {
        matches.push({ entryId: entry.entryId, prevalence });
      }
    }

    // Unmatched HIBP suffixes are intentionally discarded here.
    return matches;
  } finally {
    clearTimeout(timer);
  }
}

export async function checkPasswordsWithHibp(
  entries: Array<{ id: string; password: string }>,
  fetchImpl: typeof fetch = fetch,
): Promise<BreachCheckResult> {
  const hashed = await Promise.all(
    entries.map(async (entry) => ({
      entryId: entry.id,
      fullHash: await sha1Hex(entry.password),
    })),
  );

  const byPrefix = new Map<string, HashedEntry[]>();
  for (const entry of hashed) {
    const prefix = entry.fullHash.slice(0, 5);
    const bucket = byPrefix.get(prefix) ?? [];
    bucket.push(entry);
    byPrefix.set(prefix, bucket);
  }

  const prefixes = Array.from(byPrefix.entries());
  const matches: EntryBreachMatch[] = [];
  let cursor = 0;

  async function worker() {
    while (cursor < prefixes.length) {
      const index = cursor++;
      const [prefix, prefixEntries] = prefixes[index];
      const result = await queryPrefix(prefix, prefixEntries, fetchImpl);
      matches.push(...result);
    }
  }

  const workers = Array.from(
    { length: Math.min(MAX_CONCURRENT_REQUESTS, prefixes.length) },
    () => worker(),
  );
  await Promise.all(workers);

  return {
    matches,
    checkedEntries: entries.length,
    checkedPrefixes: prefixes.length,
  };
}
