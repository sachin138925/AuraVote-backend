export async function sendEmail({ to, subject, text, html }) {
  // Plug your provider here (SES, SendGrid, etc.)
  console.log('Email (stub):', { to, subject });
  return true;
}
