import { Router } from 'express';
import admin from '../middleware/admin.js';
import auth from '../middleware/auth.js';
import User from '../models/User.js';
import Vote from '../models/Vote.js';
import Election from '../models/Election.js';

const router = Router();

router.get('/overview', [auth, admin], async (_req, res) => {
  const [totalUsers, totalAdmins, activeElection, totalVotes] = await Promise.all([
    User.countDocuments({}),
    User.countDocuments({ isAdmin: true }),
    Election.findOne({ isActive: true }),
    Vote.countDocuments({})
  ]);

  let turnoutPct = 0;
  if (activeElection) {
    const voters = await Vote.countDocuments({ election: activeElection._id });
    const totalVoters = await User.countDocuments({ isActive: true });
    turnoutPct = totalVoters ? Math.round((voters / totalVoters) * 10000) / 100 : 0;
  }

  res.json({
    totalUsers,
    totalAdmins,
    totalVotes,
    activeElection: activeElection ? { id: activeElection._id, title: activeElection.title } : null,
    turnoutPct
  });
});

export default router;
