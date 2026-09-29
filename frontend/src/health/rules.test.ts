import { describe, it, expect } from 'vitest';
import { WeakRule, ReuseRule, OldRule, ExpirationRule, type EntryForAnalysis } from './rules';
import { analyze } from './engine';

const nowIso = new Date().toISOString();
const entry = (id: string, password: string, updatedAt = nowIso): EntryForAnalysis => ({
  id,
  password,
  updatedAt,
});

describe('WeakRule', () => {
  it('flags password shorter than 12 chars as critical', () => {
    const issues = WeakRule.apply([entry('1', 'Ab1!xyz')]);
    expect(issues).toHaveLength(1);
    expect(issues[0].severity).toBe('critical');
    expect(issues[0].message).toContain('curta');
  });

  it('accepts a strong 16-char mixed password', () => {
    const issues = WeakRule.apply([entry('1', 'Tr7!kQ9$wPz2#xL4')]);
    expect(issues).toHaveLength(0);
  });

  it('flags common password even if long', () => {
    const issues = WeakRule.apply([entry('1', 'password12345')]);
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('comum');
  });

  it('flags letters-only password', () => {
    const issues = WeakRule.apply([entry('1', 'abcdefghijklmnop')]);
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('somente letras');
  });

  it('flags digits-only password', () => {
    const issues = WeakRule.apply([entry('1', '9274613509284716')]);
    expect(issues).toHaveLength(1);
    expect(issues[0].message).toContain('somente digitos');
  });

  it('combines multiple weakness reasons', () => {
    const issues = WeakRule.apply([entry('1', '12345')]);
    expect(issues[0].message).toContain('curta');
    expect(issues[0].message).toContain('somente digitos');
  });
});

describe('ReuseRule', () => {
  it('flags the same password used in 2+ entries', () => {
    const issues = ReuseRule.apply([
      entry('a', 'SharedP@ss1!xx'),
      entry('b', 'SharedP@ss1!xx'),
      entry('c', 'DifferentP@ss2!'),
    ]);
    expect(issues).toHaveLength(2);
    expect(issues.every(i => i.severity === 'warning')).toBe(true);
    expect(issues.map(i => i.entryId).sort()).toEqual(['a', 'b']);
  });

  it('no issues when all passwords are unique', () => {
    const issues = ReuseRule.apply([
      entry('a', 'One$Trong1!abc'),
      entry('b', 'Two$Trong2!abc'),
    ]);
    expect(issues).toHaveLength(0);
  });

  it('flags all three entries sharing one password', () => {
    const issues = ReuseRule.apply([
      entry('a', 'Same$Pass1!!zz'),
      entry('b', 'Same$Pass1!!zz'),
      entry('c', 'Same$Pass1!!zz'),
    ]);
    expect(issues).toHaveLength(3);
    expect(issues[0].message).toContain('3 entradas');
  });
});

describe('OldRule', () => {
  it('flags entries older than 365 days with info severity', () => {
    const old = new Date(Date.now() - 400 * 24 * 60 * 60 * 1000).toISOString();
    const issues = OldRule.apply([entry('a', 'Whatever$1!pass', old)]);
    expect(issues).toHaveLength(1);
    expect(issues[0].severity).toBe('info');
    expect(issues[0].message).toContain('365 dias');
  });

  it('does not flag recent entries', () => {
    const recent = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString();
    const issues = OldRule.apply([entry('a', 'Whatever$1!pass', recent)]);
    expect(issues).toHaveLength(0);
  });
});


describe('ExpirationRule', () => {
  it('flags an expired credential as critical', () => {
    const expiresAt = new Date(Date.now() - 60_000).toISOString();
    const issues = ExpirationRule.apply([{ ...entry('expired', 'Fine$Trong!99zz'), expiresAt }]);
    expect(issues).toHaveLength(1);
    expect(issues[0].severity).toBe('critical');
    expect(issues[0].message).toContain('expirada');
  });

  it('flags credentials expiring within 30 days as warning', () => {
    const expiresAt = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
    const issues = ExpirationRule.apply([{ ...entry('soon', 'Fine$Trong!99zz'), expiresAt }]);
    expect(issues).toHaveLength(1);
    expect(issues[0].severity).toBe('warning');
    expect(issues[0].message).toContain('3 dia');
  });

  it('ignores credentials without expiration metadata', () => {
    const issues = ExpirationRule.apply([entry('none', 'Fine$Trong!99zz')]);
    expect(issues).toHaveLength(0);
  });
});

describe('engine.analyze', () => {
  it('aggregates counts across rules', () => {
    const old = new Date(Date.now() - 500 * 24 * 60 * 60 * 1000).toISOString();
    const report = analyze([
      entry('weak1', 'abc', nowIso),
      entry('reuse1', 'Shared$P@ss1!!!', nowIso),
      entry('reuse2', 'Shared$P@ss1!!!', nowIso),
      entry('old1', 'OldBut$Trong1!', old),
      entry('ok1', 'Fine$Trong!99zz', nowIso),
    ]);
    expect(report.totalEntries).toBe(5);
    expect(report.weakCount).toBe(1);
    expect(report.reusedCount).toBe(2);
    expect(report.oldCount).toBe(1);
    expect(report.entries).toHaveLength(5);
  });

  it('handles empty input', () => {
    const report = analyze([]);
    expect(report.totalEntries).toBe(0);
    expect(report.entries).toHaveLength(0);
  });
});
