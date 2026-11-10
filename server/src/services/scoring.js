const SEVERITY_WEIGHTS = Object.freeze({ low: 8, medium: 20, high: 35 });

function result(type, inputSummary, findings = [], recommendations = [], limitations = [], extras = {}) {
  // Deduplicate named findings so the same signal cannot inflate a score twice.
  const unique = [...new Map(findings.map(finding => [finding.name, finding])).values()];
  const indicators = unique.map(finding => {
    const weight = Number.isFinite(finding.weight) ? Math.max(0, Math.min(100, finding.weight))
      : Number.isFinite(finding.scoreContribution) ? Math.max(0, Math.min(100, finding.scoreContribution))
        : SEVERITY_WEIGHTS[finding.severity] ?? SEVERITY_WEIGHTS.low;
    return {
      category: finding.category || 'heuristic', ...finding, weight,
      scoreContribution: weight,
      recommendation: finding.recommendation || (finding.severity === 'high'
        ? 'Avoid interacting with this resource and verify it through a trusted channel.'
        : 'Review this signal in context and verify the resource independently.'),
    };
  });
  const riskScore = Math.min(100, indicators.reduce((sum, finding) => sum + finding.weight, 0));
  const threatLevel = riskScore <= 39 ? 'safe' : riskScore <= 69 ? 'medium' : 'high';
  const summary = indicators.length
    ? `${indicators.length} rule-based indicator${indicators.length === 1 ? '' : 's'} found. Heuristic analysis is not proof of malware or a guarantee of safety.`
    : 'No suspicious indicators were detected by the configured rules. This does not guarantee safety.';
  return { type, inputSummary: String(inputSummary).slice(0, 500), riskScore, threatLevel, indicators, summary, recommendations, limitations, ...extras };
}

result.SEVERITY_WEIGHTS = SEVERITY_WEIGHTS;
module.exports = result;
