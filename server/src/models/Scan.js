const mongoose = require('mongoose');
const finding = new mongoose.Schema({ name: { type: String, required: true }, category: { type: String, default: 'heuristic' }, severity: { type: String, enum: ['low','medium','high'], required: true }, weight: { type: Number, min: 0, max: 100 }, scoreContribution: { type: Number, min: 0, max: 100 }, explanation: { type: String, required: true }, evidence: { type: String, default: '' }, recommendation: { type: String } }, { _id: false });
const schema = new mongoose.Schema({
  ownerHash: { type: String, required: true, index: true, select: false },
  type: { type: String, enum: ['website','email','pdf'], required: true, index: true },
  inputSummary: { type: String, required: true, maxlength: 500 },
  riskScore: { type: Number, min: 0, max: 100, required: true },
  threatLevel: { type: String, enum: ['safe','medium','high'], required: true, index: true },
  indicators: [finding], summary: { type: String, required: true }, recommendations: [String], limitations: [String], checks: { type: mongoose.Schema.Types.Mixed, default: undefined }, status: { type: String, enum: ['complete'], default: 'complete' },
}, { timestamps: true });
schema.set('toJSON', { transform(_doc, value) { delete value.ownerHash; return value; } });
schema.index({ ownerHash: 1, createdAt: -1 });
module.exports = mongoose.model('Scan', schema);
