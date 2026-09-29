import type { HealthReport } from './engine';

export function computeScore(report: HealthReport): number {
  if (report.totalEntries === 0) return 100;
  const raw =
    100 - report.breachedCount * 20 - report.weakCount * 15 - report.reusedCount * 10;
  return Math.max(0, Math.min(100, raw));
}
