import { describe, it, expect } from 'vitest';
import { computeScore } from './score';
import type { HealthReport } from './engine';

const report = (
  totalEntries: number,
  weakCount: number,
  reusedCount: number,
  oldCount = 0,
  breachedCount = 0,
): HealthReport => ({
  totalEntries,
  weakCount,
  reusedCount,
  oldCount,
  breachedCount,
  entries: [],
});

describe('computeScore', () => {
  it('returns 100 for empty vault', () => {
    expect(computeScore(report(0, 0, 0))).toBe(100);
  });

  it('returns 85 with one weak entry', () => {
    expect(computeScore(report(1, 1, 0))).toBe(85);
  });

  it('returns 90 with one reused entry', () => {
    expect(computeScore(report(2, 0, 1))).toBe(90);
  });

  it('returns 75 with one weak and one reused', () => {
    expect(computeScore(report(2, 1, 1))).toBe(75);
  });

  it('subtracts 20 points per breached entry', () => {
    expect(computeScore(report(2, 0, 0, 0, 1))).toBe(80);
  });

  it('clamps at 0 for many violations', () => {
    expect(computeScore(report(10, 8, 4, 0, 2))).toBe(0);
  });
});
