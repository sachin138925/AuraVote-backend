import fetch from 'node-fetch';

export async function verifyRecaptcha(token, ip) {
  if (!process.env.RECAPTCHA_SECRET) return true; // allow in dev if not set
  const params = new URLSearchParams();
  params.append('secret', process.env.RECAPTCHA_SECRET);
  params.append('response', token);
  if (ip) params.append('remoteip', ip);

  const res = await fetch('https://www.google.com/recaptcha/api/siteverify', {
    method: 'POST',
    body: params
  });
  const data = await res.json();
  return !!data.success;
}
