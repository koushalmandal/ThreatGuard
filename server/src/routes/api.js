const express = require('express');
const multer = require('multer');
const crypto = require('node:crypto');
const mongoose = require('mongoose');
const Scan = require('../models/Scan');
const website = require('../services/website');
const email = require('../services/email');
const pdf = require('../services/pdf');
const validatePdfUpload = require('../services/pdfUpload');
const { completedScanFilter, historySort } = require('../services/scanQueries');
const router = express.Router();
const maxMb = Math.max(1, Math.min(20, Number(process.env.UPLOAD_MAX_MB) || 10));
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxMb * 1024 * 1024, files: 1 } });
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
function owner(req, res, next) {
  const token = req.get('x-anonymous-token') || '';
  if (!/^[A-Za-z0-9_-]{40,100}$/.test(token)) return res.status(401).json({ error: 'Browser scan capability is missing or invalid.' });
  req.ownerHash = crypto.createHash('sha256').update(token).digest('hex'); next();
}
async function save(req, res, data) {
  const scan = await Scan.create({ ...data, ownerHash: req.ownerHash, status: 'complete' });
  return res.status(201).json({ scan });
}
// Scan writes, private history/reports, and analytics all require the same
// browser capability. Keep public/system routes outside these protected groups.
router.use(['/scans', '/dashboard'], owner);
router.post('/scans/website', asyncRoute(async (req, res) => save(req, res, await website(req.body?.url))));
router.post('/scans/email', asyncRoute(async (req, res) => save(req, res, await email(req.body || {}))));
router.post('/scans/pdf', upload.single('file'), asyncRoute(async (req, res) => {
  validatePdfUpload(req.file);
  let data;
  try { data = await pdf(req.file.buffer); }
  catch (error) {
    if (error.status) throw error;
    throw Object.assign(new Error('Could not read this PDF. It may be damaged, encrypted, or unsupported.'), { status: 400 });
  }
  data.checks.fileValidation = { status: 'passed', sizeBytes: req.file.size, mimeType: req.file.mimetype };
  return save(req, res, data);
}));
router.get('/scans', asyncRoute(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1), limit = Math.min(50, Math.max(1, parseInt(req.query.limit, 10) || 10));
  const filter = { ownerHash: req.ownerHash };
  if (['website','email','pdf'].includes(req.query.type)) filter.type = req.query.type;
  if (req.query.level === 'safe') filter.threatLevel = { $in: ['safe','low'] };
  if (req.query.level === 'medium') filter.threatLevel = { $in: ['medium','suspicious'] };
  if (req.query.level === 'high') filter.threatLevel = { $in: ['high','malicious'] };
  if (req.query.q) filter.inputSummary = { $regex: String(req.query.q).slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), $options: 'i' };
  const [scans, total] = await Promise.all([Scan.find(filter).sort(historySort(req.query.sort)).skip((page - 1) * limit).limit(limit), Scan.countDocuments(filter)]);
  res.json({ scans, total, page, pages: Math.ceil(total / limit) });
}));
router.delete('/scans', asyncRoute(async (req, res) => {
  const result = await Scan.deleteMany({ ownerHash: req.ownerHash });
  res.json({ ok: true, deleted: result.deletedCount });
}));
router.get('/scans/:id', asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ error: 'Report not found.' });
  const scan = await Scan.findOne({ _id: req.params.id, ownerHash: req.ownerHash });
  if (!scan) return res.status(404).json({ error: 'Report not found.' });
  res.json({ scan });
}));
router.delete('/scans/:id', asyncRoute(async (req, res) => {
  const deleted = await Scan.findOneAndDelete({ _id: req.params.id, ownerHash: req.ownerHash });
  if (!deleted) return res.status(404).json({ error: 'Scan not found.' });
  res.json({ ok: true });
}));
router.get('/dashboard/stats', asyncRoute(async (req, res) => {
  const completedFilter = completedScanFilter(req.ownerHash);
  const [total, groups, typeGroups, recent] = await Promise.all([
    Scan.countDocuments(completedFilter),
    Scan.aggregate([{ $match: completedFilter }, { $group: { _id: '$threatLevel', count: { $sum: 1 } } }]),
    Scan.aggregate([{ $match: completedFilter }, { $group: { _id: '$type', count: { $sum: 1 } } }]),
    Scan.find(completedFilter).sort({ createdAt: -1, _id: -1 }).limit(6),
  ]);
  const levels = { safe: 0, medium: 0, high: 0 }, types = { website: 0, email: 0, pdf: 0 };
  const levelAliases = { safe: 'safe', low: 'safe', medium: 'medium', suspicious: 'medium', high: 'high', malicious: 'high' };
  groups.forEach(x => { const level = levelAliases[x._id]; if (level) levels[level] += x.count; });
  typeGroups.forEach(x => { if (Object.hasOwn(types, x._id)) types[x._id] += x.count; });
  res.json({ total, levels, types, recent });
}));
router.get('/dashboard/activity', asyncRoute(async (req, res) => {
  const since = new Date(); since.setDate(since.getDate() - 29);
  const match = { ...completedScanFilter(req.ownerHash), createdAt: { $gte: since } };
  if (['website','email','pdf'].includes(req.query.type)) match.type = req.query.type;
  const activity = await Scan.aggregate([{ $match: match }, { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } }, { $sort: { _id: 1 } }]);
  res.json({ activity });
}));
module.exports = router;
