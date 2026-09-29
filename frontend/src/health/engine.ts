import type { EntryForAnalysis, EntryIssue, HealthRule, Issue } from './rules';
import { defaultRules } from './rules';

export interface EntryHealth {
  entryId: string;
  issues: (Issue & { entryId?: string })[];
  hasWeak: boolean;
  hasReuse: boolean;
  hasOld: boolean;
}

export interface HealthReport {
  totalEntries: number;
  weakCount: number;
  reusedCount: number;
  oldCount: number;
  breachedCount: number;
  entries: EntryHealth[];
}

export function analyze(entries: EntryForAnalysis[], rules: HealthRule[] = defaultRules): HealthReport {
  const allIssues: EntryIssue[] = [];
  for (const rule of rules) {
    const produced = rule.apply(entries) as EntryIssue[];
    for (const issue of produced) allIssues.push(issue);
  }

  const byEntry = new Map<string, EntryHealth>();
  for (const e of entries) {
    byEntry.set(e.id, {
      entryId: e.id,
      issues: [],
      hasWeak: false,
      hasReuse: false,
      hasOld: false,
    });
  }

  for (const issue of allIssues) {
    const bucket = byEntry.get(issue.entryId);
    if (!bucket) continue;
    bucket.issues.push(issue);
    if (issue.ruleId === 'weak-password') bucket.hasWeak = true;
    if (issue.ruleId === 'reuse-password') bucket.hasReuse = true;
    if (issue.ruleId === 'old-password') bucket.hasOld = true;
  }

  let weakCount = 0;
  let reusedCount = 0;
  let oldCount = 0;
  for (const eh of byEntry.values()) {
    if (eh.hasWeak) weakCount++;
    if (eh.hasReuse) reusedCount++;
    if (eh.hasOld) oldCount++;
  }

  return {
    totalEntries: entries.length,
    weakCount,
    reusedCount,
    oldCount,
    breachedCount: 0,
    entries: Array.from(byEntry.values()),
  };
}
