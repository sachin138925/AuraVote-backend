import { Router } from 'express';
import auth from '../middleware/auth.js';
import Election from '../models/Election.js';
import Vote from '../models/Vote.js';
import User from '../models/User.js';
import AuditLog from '../models/AuditLog.js';

const router = Router();

// Client calls this after on-chain success to persist tx hash & mark voted
router.post('/record', auth, async (req, res) => {
  const { electionId, candidateName, txHash, network } = req.body;

  const election = await Election.findById(electionId);
  if (!election || !election.isActive) return res.status(400).json({ msg: 'Invalid/Inactive election' });

  // idempotent per user per election
  const existing = await Vote.findOne({ user: req.user.id, election: electionId });
  if (existing) return res.status(409).json({ msg: 'Already recorded for this election' });

  const vote = await Vote.create({
    user: req.user.id,
    election: election._id,
    candidateName,
    txHash,
    network
  });

  await User.findByIdAndUpdate(req.user.id, { hasVoted: true });
  await AuditLog.create({ actor: req.user.id, action: 'CAST_VOTE', metadata: { electionId, candidateName, txHash } });

  // notify clients to refresh results
  const io = req.app.get('io');
  io.emit('results:update', { electionId });

  res.status(201).json({ msg: 'Vote recorded', voteId: vote._id });
});

export default router;
