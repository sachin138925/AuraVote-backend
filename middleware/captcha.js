import { verifyRecaptcha } from '../utils/recaptcha.js';

export default async function captcha(req, res, next) {
  // Expecting `recaptchaToken` in body
  const token = req.body.recaptchaToken;
  if (!token) return res.status(400).json({ msg: 'Captcha token missing' });
  try {
    const ok = await verifyRecaptcha(token, req.ip);
    if (!ok) return res.status(400).json({ msg: 'Captcha verification failed' });
    next();
  } catch {
    return res.status(500).json({ msg: 'Captcha service error' });
  }
}
