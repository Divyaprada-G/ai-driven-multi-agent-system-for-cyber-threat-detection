/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Risk Scoring Engine Verification CLI/Console Runner
 */

import { runRiskScoringTests } from '../services/riskScoring/riskTests';

export function runStage8Tests() {
  console.log('=== RUNNING STAGE 8 RISK SCORING & PRIORITIZATION VERIFICATION SUITE ===\n');
  const summary = runRiskScoringTests();

  summary.results.forEach(res => {
    if (res.passed) {
      console.log(`[PASS] ${res.id}: ${res.name}`);
      console.log(`       Actual: ${res.actual}`);
    } else {
      console.error(`[FAIL] ${res.id}: ${res.name}`);
      console.error(`       Expected: ${res.expected}`);
      console.error(`       Actual:   ${res.actual}`);
    }
  });

  console.log(`\nVerification Suite Complete: ${summary.passed}/${summary.total} Passed. All Passed: ${summary.allPassed}`);
  return summary;
}

runStage8Tests();
