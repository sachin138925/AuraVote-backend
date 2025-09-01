import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import qrcode from 'qrcode';
import speakeasy from 'speakeasy';

import User from '../models/User.js';
import RefreshToken from '../models/RefreshToken.js';
import auth from '../middleware/auth.js';
import captcha from '../middleware/captcha.js';
import { signAccessToken, signRefreshToken, rotateRefreshToken } from '../utils/jwt.js';
import AuditLog from '../models/AuditLog.js';

const router = Router();

// Get current user
router.get('/', auth, async (req, res) => {
  const user = await User.findById(req.user.id).select('-password -mfaSecret');
  res.json(user);
});

// Register
router.post('/register', captcha, async (req, res) => {
  const { email, password } = req.body;
  let user = await User.findOne({ email });
  if (user) return res.status(400).json({ msg: 'User already exists' });
  const hash = await bcrypt.hash(password, 10);
  user = await User.create({ email, password: hash });
  const access = signAccessToken(user.id);
  const refresh = await signRefreshToken(user.id);
  await AuditLog.create({ actor: user._id, action: 'REGISTER' });
  res.status(201).json({ token: access, refreshToken: refresh, user: { id: user.id, email: user.email, isAdmin: user.isAdmin } });
});

// Login
router.post('/login', captcha, async (req, res) => {
  const { email, password, mfaToken } = req.body;
  const user = await User.findOne({ email });
  if (!user || !user.isActive) return res.status(400).json({ msg: 'Invalid credentials' });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(400).json({ msg: 'Invalid credentials' });

  // If MFA enabled, require TOTP
  if (user.mfaEnabled) {
    if (!mfaToken) return res.status(401).json({ msg: 'MFA token required' });
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 1
    });
    if (!verified) return res.status(401).json({ msg: 'Invalid MFA token' });
  }

  const access = signAccessToken(user.id);
  const refresh = await signRefreshToken(user.id);
  await AuditLog.create({ actor: user._id, action: 'LOGIN' });
  res.json({
    token: access,
    refreshToken: refresh,
    user: { id: user.id, email: user.email, walletAddress: user.walletAddress, hasVoted: user.hasVoted, isAdmin: user.isAdmin }
  });
});

// Refresh token
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  try {
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const doc = await RefreshToken.findOne({ token: refreshToken, revoked: false });
    if (!doc || doc.user.toString() !== decoded.user.id) throw new Error();
    const newAccess = signAccessToken(decoded.user.id);
    const newRefresh = await rotateRefreshToken(refreshToken);
    res.json({ token: newAccess, refreshToken: newRefresh });
  } catch {
    res.status(401).json({ msg: 'Invalid refresh token' });
  }
});

// Logout (revoke refresh)
router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  await RefreshToken.findOneAndUpdate({ token: refreshToken }, { revoked: true });
  res.json({ msg: 'Logged out' });
});

// Bind wallet
router.post('/wallet', auth, async (req, res) => {
  const { walletAddress } = req.body;
  const exists = await User.findOne({ walletAddress });
  if (exists && exists._id.toString() !== req.user.id) return res.status(400).json({ msg: 'Wallet already in use' });
  const user = await User.findByIdAndUpdate(req.user.id, { walletAddress }, { new: true }).select('-password -mfaSecret');
  res.json(user);
});
router.delete('/wallet', auth, async (req, res) => {
  const user = await User.findByIdAndUpdate(req.user.id, { walletAddress: '' }, { new: true }).select('-password -mfaSecret');
  res.json(user);
});

// MFA setup (admin or user)
router.post('/mfa/setup', auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  const secret = speakeasy.generateSecret({ name: `HybridVote (${user.email})` });
  const otpAuthUrl = secret.otpauth_url;
  const qr = await qrcode.toDataURL(otpAuthUrl);
  user.mfaSecret = secret.base32;
  await user.save();
  res.json({ qrCodeDataUrl: qr, secret: secret.base32 });
});

router.post('/mfa/enable', auth, async (req, res) => {
  const { token } = req.body;
  const user = await User.findById(req.user.id);
  const ok = speakeasy.totp.verify({ secret: user.mfaSecret, encoding: 'base32', token, window: 1 });
  if (!ok) return res.status(400).json({ msg: 'Invalid token' });
  user.mfaEnabled = true;
  await user.save();
  res.json({ msg: 'MFA enabled' });
});

router.post('/mfa/disable', auth, async (req, res) => {
  const user = await User.findById(req.user.id);
  user.mfaEnabled = false;
  user.mfaSecret = '';
  await user.save();
  res.json({ msg: 'MFA disabled' });
});

export default router;
