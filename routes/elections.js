import { Router } from 'express';
import { z } from 'zod';
import auth from '../middleware/auth.js';
import admin from '../middleware/admin.js';
import Election from '../models/Election.js';
import AuditLog from '../models/AuditLog.js';

const router = Router();

const electionSchema = z.object({
  title: z.string().min(3),
  description: z.string().min(10),
  candidates: z.array(z.object({ name: z.string().min(1), party: z.string().optional() })).min(2),
  startDate: z.string(),
  endDate: z.string()
});

router.get('/', auth, async (_req, res) => {
  const data = await Election.find().sort({ startDate: -1 });
  res.json(data);
});

router.get('/active', auth, async (_req, res) => {
  const active = await Election.findOne({ isActive: true });
  if (!active) return res.status(404).json({ msg: 'No active election found' });
  res.json(active);
});

// Create election
router.post('/', [auth, admin], async (req, res) => {
  const parsed = electionSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ msg: 'Invalid payload', issues: parsed.error.issues });

  const { title, description, candidates, startDate, endDate } = parsed.data;
  const s = new Date(startDate), e = new Date(endDate);
  if (e <= s) return res.status(400).json({ msg: 'End date must be after start date' });

  const election = await Election.create({ title, description, candidates, startDate: s, endDate: e });
  await AuditLog.create({ action: 'CREATE_ELECTION', metadata: { electionId: election._id } });
  res.status(201).json(election);
});

// Toggle status
router.put('/:id/status', [auth, admin], async (req, res) => {
  const { isActive } = req.body;
  const election = await Election.findByIdAndUpdate(req.params.id, { isActive }, { new: true });
  if (!election) return res.status(404).json({ msg: 'Election not found' });
  await AuditLog.create({ action: isActive ? 'ELECTION_STARTED' : 'ELECTION_ENDED', metadata: { electionId: election._id } });
  res.json(election);
});

export default router;
