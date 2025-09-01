import { logger } from '../utils/logger.js';

export default function errorHandler(err, req, res, _next) {
  logger.error('Unhandled error', { err, path: req.path });
  if (res.headersSent) return;
  res.status(err.status || 500).json({ msg: err.message || 'Server error' });
}
