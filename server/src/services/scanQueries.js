const VALID_TYPES = ['website', 'email', 'pdf'];
const VALID_LEVELS = ['safe', 'low', 'medium', 'suspicious', 'high', 'malicious'];

function completedScanFilter(ownerHash) {
  return {
    ownerHash,
    status: 'complete',
    type: { $in: VALID_TYPES },
    riskScore: { $type: 'number', $gte: 0, $lte: 100 },
    // Exclude missing/unknown categories instead of silently treating them as safe.
    threatLevel: { $in: VALID_LEVELS },
  };
}

function historySort(sortBy) {
  return sortBy === 'risk'
    ? { riskScore: -1, createdAt: -1, _id: -1 }
    : { createdAt: -1, _id: -1 };
}

module.exports = { completedScanFilter, historySort };
