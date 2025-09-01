import { Router } from 'express';
import bcrypt from 'bcryptjs';
import auth from '../middleware/auth.js';
import User from '../models/User.js';
import Vote from '../models/Vote.js';

const router = Router();

// Update email/password
router.put('/me', auth, async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;
  const user = await User.findById(req.user.id);
  if (email) user.email = email.toLowerCase();
  if (newPassword) {
    const ok = await bcrypt.compare(currentPassword || '', user.password);
    if (!ok) return res.status(400).json({ msg: 'Current password incorrect' });
    user.password = await bcrypt.hash(newPassword, 10);
  }
  await user.save();
  res.json({ msg: 'Profile updated' });
});

// My votes history
router.get('/me/votes', auth, async (req, res) => {
  const votes = await Vote.find({ user: req.user.id }).populate('election', 'title startDate endDate');
  res.json(votes);
});

export default router;
