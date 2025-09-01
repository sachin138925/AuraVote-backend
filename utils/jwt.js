import jwt from 'jsonwebtoken';
import RefreshToken from '../models/RefreshToken.js';

export const signAccessToken = (userId) =>
  jwt.sign({ user: { id: userId } }, process.env.JWT_SECRET, { expiresIn: '1h' });

export const signRefreshToken = async (userId) => {
  const token = jwt.sign({ user: { id: userId } }, process.env.JWT_REFRESH_SECRET, { expiresIn: '7d' });
  const doc = await RefreshToken.create({
    user: userId,
    token,
    expiresAt: new Date(Date.now() + 7 * 24 * 3600 * 1000)
  });
  return doc.token;
};

export const rotateRefreshToken = async (oldToken) => {
  try {
    const doc = await RefreshToken.findOne({ token: oldToken, revoked: false });
    if (!doc) throw new Error('Invalid refresh token');
    doc.revoked = true;
    await doc.save();
    return signRefreshToken(doc.user);
  } catch (e) {
    throw new Error('Invalid refresh token');
  }
};
