// Diff between two ArbPackage snapshots. Stored alongside the new
// package so the viewer and dashboard can answer "what changed since
// last ARB review?". Only includes coarse, decision-relevant deltas —
// we deliberately don't produce a JSON-Patch of every byte.

import { ArbPackage, PackageDiff } from '../types/assessment';

function setDiff<T>(prev: Set<T>, next: Set<T>): { added: T[]; removed: T[] } {
  return {
    added: [...next].filter(x => !prev.has(x)),
    removed: [...prev].filter(x => !next.has(x))
  };
}

function changedOrNull<T>(from: T, to: T): { from: T; to: T } | null {
  return from === to ? null : { from, to };
}

export function diffPackages(prev: ArbPackage, next: ArbPackage): PackageDiff {
  const prevControls = new Set(prev.ssp.map(c => c.id));
  const nextControls = new Set(next.ssp.map(c => c.id));
  const controls = setDiff(prevControls, nextControls);

  const prevComps = new Set(prev.architecture.components.map(c => c.name));
  const nextComps = new Set(next.architecture.components.map(c => c.name));
  const comps = setDiff(prevComps, nextComps);

  const order: Record<string, number> = { Low: 0, Medium: 1, High: 2, Critical: 3 };
  const sum = (xs: string[]) => xs.reduce((acc, x) => acc + (order[x] ?? 0), 0);
  const inherentDelta = sum(next.threatModel.map(t => t.inherentRisk)) - sum(prev.threatModel.map(t => t.inherentRisk));
  const residualDelta = sum(next.threatModel.map(t => t.residualRisk)) - sum(prev.threatModel.map(t => t.residualRisk));

  const cov = (p: ArbPackage, k: 'Full' | 'Partial' | 'Gap') =>
    p.complianceMappings.filter(m => m.coverage === k).length;
  const complianceCoverageDelta = {
    full: cov(next, 'Full') - cov(prev, 'Full'),
    partial: cov(next, 'Partial') - cov(prev, 'Partial'),
    gap: cov(next, 'Gap') - cov(prev, 'Gap')
  };

  const postureChange = changedOrNull(prev.executiveSummary.riskPosture, next.executiveSummary.riskPosture);
  const goNoGoChange = changedOrNull(prev.executiveSummary.goNoGoAdvice, next.executiveSummary.goNoGoAdvice);
  const categoryChange = changedOrNull(prev.categorization.overallCategorization, next.categorization.overallCategorization);
  const recoveryTierChange = changedOrNull(prev.recovery.availabilityTier, next.recovery.availabilityTier);

  const highlights: string[] = [];
  if (postureChange) highlights.push(`Posture moved from ${postureChange.from} to ${postureChange.to}.`);
  if (goNoGoChange) highlights.push(`ARB recommendation moved from "${goNoGoChange.from}" to "${goNoGoChange.to}".`);
  if (categoryChange) highlights.push(`FIPS 199 category moved from ${categoryChange.from} to ${categoryChange.to}.`);
  if (recoveryTierChange) highlights.push(`Recovery tier moved from ${recoveryTierChange.from} to ${recoveryTierChange.to}.`);
  if (controls.added.length) highlights.push(`Added ${controls.added.length} control(s): ${controls.added.slice(0, 6).join(', ')}${controls.added.length > 6 ? '…' : ''}.`);
  if (controls.removed.length) highlights.push(`Removed ${controls.removed.length} control(s): ${controls.removed.slice(0, 6).join(', ')}${controls.removed.length > 6 ? '…' : ''}.`);
  if (comps.added.length) highlights.push(`Added ${comps.added.length} component(s).`);
  if (comps.removed.length) highlights.push(`Removed ${comps.removed.length} component(s).`);
  if (complianceCoverageDelta.gap > 0) highlights.push(`${complianceCoverageDelta.gap} new compliance gap(s) opened.`);
  if (complianceCoverageDelta.gap < 0) highlights.push(`${-complianceCoverageDelta.gap} compliance gap(s) closed.`);
  if (inherentDelta !== 0 || residualDelta !== 0) highlights.push(`Risk-score delta — inherent ${inherentDelta >= 0 ? '+' : ''}${inherentDelta}, residual ${residualDelta >= 0 ? '+' : ''}${residualDelta}.`);
  if (highlights.length === 0) highlights.push('No decision-relevant changes since previous version.');

  return {
    fromVersion: prev.packageVersion,
    toVersion: next.packageVersion,
    fromGeneratedAt: prev.generatedAt,
    toGeneratedAt: next.generatedAt,
    postureChange,
    goNoGoChange,
    categoryChange,
    recoveryTierChange,
    controlsAdded: controls.added,
    controlsRemoved: controls.removed,
    componentsAdded: comps.added,
    componentsRemoved: comps.removed,
    threatCountDelta: { inherent: inherentDelta, residual: residualDelta },
    complianceCoverageDelta,
    highlights
  };
}
