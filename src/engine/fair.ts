// FAIR (Factor Analysis of Information Risk) quantification with a
// Monte Carlo simulation of Annualized Loss Expectancy per residual
// risk. Inputs are derived deterministically from the existing risk
// model so the platform produces a defensible first-order $$ band
// even when the user hasn't supplied detailed FAIR factors.
//
//   Loss Event Frequency (LEF) = Threat Event Frequency × Vulnerability
//   Loss Magnitude (LM)        = Primary + Secondary loss
//   ALE                        = LEF × LM
//
// Each factor is modelled as a uniform band; the Monte Carlo samples
// LEF and LM independently and reports percentiles + mean.

import { Assessment, FairAnalysis, FairFinding, ResidualRisk } from '../types/assessment';

const ITERATIONS = 5000;

// Threat Event Frequency (events/year) bands by likelihood label.
const TEF: Record<'Low' | 'Medium' | 'High' | 'Critical', [number, number]> = {
  Low:      [0.01, 0.1],
  Medium:   [0.1, 1],
  High:     [1, 10],
  Critical: [3, 25]
};

// Loss Magnitude (USD per event) bands by residual severity.
const LM: Record<'Low' | 'Medium' | 'High' | 'Critical', [number, number]> = {
  Low:      [1_000, 50_000],
  Medium:   [50_000, 500_000],
  High:     [500_000, 5_000_000],
  Critical: [5_000_000, 50_000_000]
};

// Vulnerability is the probability that a threat event becomes a loss
// event once detection / preventive controls are in place. We scale
// upward from very-low to high based on the residual rating.
const VULN: Record<'Low' | 'Medium' | 'High' | 'Critical', [number, number]> = {
  Low:      [0.01, 0.10],
  Medium:   [0.10, 0.30],
  High:     [0.30, 0.60],
  Critical: [0.60, 0.95]
};

function uniform(low: number, high: number): number {
  return low + Math.random() * (high - low);
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const idx = Math.min(sorted.length - 1, Math.max(0, Math.floor(p * sorted.length)));
  return sorted[idx]!;
}

function simulate(tefBand: [number, number], vulnBand: [number, number], lmBand: [number, number]): { p10: number; p50: number; p90: number; mean: number } {
  const samples = new Array<number>(ITERATIONS);
  let sum = 0;
  for (let i = 0; i < ITERATIONS; i++) {
    const tef = uniform(tefBand[0], tefBand[1]);
    const vuln = uniform(vulnBand[0], vulnBand[1]);
    const lm = uniform(lmBand[0], lmBand[1]);
    const ale = tef * vuln * lm;
    samples[i] = ale;
    sum += ale;
  }
  samples.sort((a, b) => a - b);
  return { p10: percentile(samples, 0.10), p50: percentile(samples, 0.50), p90: percentile(samples, 0.90), mean: sum / ITERATIONS };
}

function tefForRisk(r: ResidualRisk): [number, number] {
  return TEF[r.inherentRisk];
}
function vulnForRisk(r: ResidualRisk): [number, number] {
  return VULN[r.residualRisk];
}
function lmForRisk(r: ResidualRisk, a: Assessment): [number, number] {
  const base = LM[r.residualRisk];
  // Adjust by user population — bigger blast radius = bigger primary loss band
  const popMult = a.population.userCount === '10000+' ? 1.5 : a.population.userCount === '1000-10000' ? 1.0 : 0.7;
  return [base[0] * popMult, base[1] * popMult];
}

export function quantifyFair(a: Assessment, risks: ResidualRisk[]): FairAnalysis {
  const perRisk: FairFinding[] = [];
  for (const r of risks) {
    const tef = tefForRisk(r);
    const vuln = vulnForRisk(r);
    const lm = lmForRisk(r, a);
    const sim = simulate(tef, vuln, lm);
    perRisk.push({
      riskId: r.id,
      description: r.description,
      tefLow: tef[0], tefHigh: tef[1],
      vulnLow: vuln[0], vulnHigh: vuln[1],
      lmLow: lm[0], lmHigh: lm[1],
      aleP10: Math.round(sim.p10),
      aleP50: Math.round(sim.p50),
      aleP90: Math.round(sim.p90),
      aleMean: Math.round(sim.mean),
      rationale: `Inherent=${r.inherentRisk}, residual=${r.residualRisk}, population=${a.population.userCount}. TEF ${tef[0]}–${tef[1]} events/yr × Vuln ${(vuln[0]*100).toFixed(0)}–${(vuln[1]*100).toFixed(0)}% × LM $${lm[0].toLocaleString()}–$${lm[1].toLocaleString()}.`
    });
  }
  // Portfolio rollup — sum-distribution by adding sample means is a
  // first-order approximation; for tight bounds we'd convolve. For
  // ARB-level reporting this is adequate.
  const total: { p10: number; p50: number; p90: number; mean: number } = {
    p10: perRisk.reduce((s, r) => s + r.aleP10, 0),
    p50: perRisk.reduce((s, r) => s + r.aleP50, 0),
    p90: perRisk.reduce((s, r) => s + r.aleP90, 0),
    mean: perRisk.reduce((s, r) => s + r.aleMean, 0)
  };
  return {
    perRisk,
    portfolio: { aleP10: Math.round(total.p10), aleP50: Math.round(total.p50), aleP90: Math.round(total.p90), aleMean: Math.round(total.mean) },
    iterations: ITERATIONS,
    notes: [
      'TEF and LM bands are deterministic defaults derived from inherent and residual risk ratings.',
      'For higher-fidelity FAIR analysis, replace the bands with calibrated subject-matter-expert estimates.',
      'Portfolio rollup is a sum of per-risk percentiles (first-order approximation, not a convolution).'
    ]
  };
}
