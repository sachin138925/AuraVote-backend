import { Router } from 'express';
import auth from '../middleware/auth.js';
import admin from '../middleware/admin.js';
import User from '../models/User.js';

const router = Router();

router.get('/users', [auth, admin], async (_req, res) => {
  const users = await User.find().select('-password -mfaSecret');
  res.json(users);
});

router.put('/users/:id/role', [auth, admin], async (req, res) => {
  const { isAdmin } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { isAdmin: !!isAdmin }, { new: true }).select('-password -mfaSecret');
  if (!user) return res.status(404).json({ msg: 'User not found' });
  res.json(user);
});

router.put('/users/:id/status', [auth, admin], async (req, res) => {
  const { isActive } = req.body;
  const user = await User.findByIdAndUpdate(req.params.id, { isActive: !!isActive }, { new: true }).select('-password -mfaSecret');
  if (!user) return res.status(404).json({ msg: 'User not found' });
  res.json(user);
});

export default router;
