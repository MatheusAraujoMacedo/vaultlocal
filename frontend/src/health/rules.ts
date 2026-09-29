export type Severity = 'critical' | 'warning' | 'info';

export interface Issue {
  ruleId: string;
  severity: Severity;
  message: string;
}

export interface EntryForAnalysis {
  id: string;
  password: string;
  updatedAt: string; // ISO 8601 date string
  expiresAt?: string | null; // optional expiration metadata
}

export interface HealthRule {
  id: string;
  apply(entries: EntryForAnalysis[]): EntryIssue[];
}
export interface EntryIssue extends Issue {
  entryId: string;
}

const COMMON_PASSWORDS = new Set([
  'password', 'password123', '12345678', '123456789', '1234567890',
  'qwerty', 'qwerty123', 'abc123', 'letmein', 'admin', 'welcome',
  'iloveyou', 'monkey', 'dragon', 'football', 'sunshine', 'master',
  'shadow', 'superman', 'michael', 'ninja', 'mustang', 'hunter',
  'hunter2', 'trustno1', 'whatever', 'charlie', 'donald', 'ginger',
  'solo', 'starwars', 'pokemon', 'password1', 'passw0rd', 'p@ssw0rd',
  'password12345', 'password123456',
]);

export const WeakRule: HealthRule & { apply(entries: EntryForAnalysis[]): EntryIssue[] } = {
  id: 'weak-password',
  apply(entries: EntryForAnalysis[]): EntryIssue[] {
    const issues: EntryIssue[] = [];
    for (const entry of entries) {
      const pwd = entry.password ?? '';
      const reasons: string[] = [];

      if (pwd.length < 12) reasons.push('senha curta (menos de 12 caracteres)');
      if (COMMON_PASSWORDS.has(pwd.toLowerCase())) reasons.push('senha comum');
      if (/^[a-zA-Z]+$/.test(pwd)) reasons.push('somente letras');
      if (/^[0-9]+$/.test(pwd)) reasons.push('somente digitos');

      if (reasons.length > 0) {
        issues.push({
          ruleId: WeakRule.id,
          entryId: entry.id,
          severity: 'critical',
          message: `Senha fraca: ${reasons.join(', ')}`,
        });
      }
    }
    return issues;
  },
};

// ReuseRule: same password in 2+ entries
export const ReuseRule: HealthRule & { apply(entries: EntryForAnalysis[]): EntryIssue[] } = {
  id: 'reuse-password',
  apply(entries: EntryForAnalysis[]): EntryIssue[] {
    const byPassword = new Map<string, string[]>();
    for (const e of entries) {
      const list = byPassword.get(e.password) ?? [];
      list.push(e.id);
      byPassword.set(e.password, list);
    }
    const issues: EntryIssue[] = [];
    for (const [, ids] of byPassword) {
      if (ids.length >= 2) {
        for (const entryId of ids) {
          issues.push({
            ruleId: ReuseRule.id,
            entryId,
            severity: 'warning',
            message: `Senha reutilizada em ${ids.length} entradas`,
          });
        }
      }
    }
    return issues;
  },
};

// OldRule: password older than 365 days (informational, neutral message)
export const OldRule: HealthRule & { apply(entries: EntryForAnalysis[]): EntryIssue[] } = {
  id: 'old-password',
  apply(entries: EntryForAnalysis[]): EntryIssue[] {
    const issues: EntryIssue[] = [];
    const now = Date.now();
    const YEAR_MS = 365 * 24 * 60 * 60 * 1000;
    for (const entry of entries) {
      const updated = new Date(entry.updatedAt).getTime();
      if (!Number.isNaN(updated) && now - updated > YEAR_MS) {
        issues.push({
          ruleId: OldRule.id,
          entryId: entry.id,
          severity: 'info',
          message: 'Senha com mais de 365 dias desde a ultima atualizacao',
        });
      }
    }
    return issues;
  },
};

export const ExpirationRule: HealthRule & { apply(entries: EntryForAnalysis[]): EntryIssue[] } = {
  id: 'expiring-secret',
  apply(entries: EntryForAnalysis[]): EntryIssue[] {
    const issues: EntryIssue[] = [];
    const now = Date.now();
    const SOON_MS = 30 * 24 * 60 * 60 * 1000;
    for (const entry of entries) {
      if (!entry.expiresAt) continue;
      const expires = new Date(entry.expiresAt).getTime();
      if (Number.isNaN(expires)) continue;
      if (expires <= now) {
        issues.push({
          ruleId: ExpirationRule.id,
          entryId: entry.id,
          severity: 'critical',
          message: 'Credencial expirada; considere gerar uma nova senha',
        });
      } else if (expires - now <= SOON_MS) {
        const days = Math.max(1, Math.ceil((expires - now) / (24 * 60 * 60 * 1000)));
        issues.push({
          ruleId: ExpirationRule.id,
          entryId: entry.id,
          severity: 'warning',
          message: 'Credencial expira em ' + days + ' dia(s)',
        });
      }
    }
    return issues;
  },
};

export const defaultRules: HealthRule[] = [WeakRule, ReuseRule, OldRule, ExpirationRule];
