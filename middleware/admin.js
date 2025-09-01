import User from '../models/User.js';

export default async function admin(req, res, next) {
  const user = await User.findById(req.user.id);
  if (!user || !user.isAdmin) return res.status(403).json({ msg: 'Admin only' });
  next();
}
