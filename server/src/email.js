/**
 * Email delivery for verification codes and password resets.
 *
 * Configured via environment variables (set these in Railway → Variables):
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM
 *
 * When SMTP is NOT configured the server runs in "dev email" mode: codes are
 * logged to the server console and returned to the client so the flow is
 * testable without a provider. In that mode email verification is a
 * placeholder — configure SMTP before relying on it in production.
 */
import nodemailer from 'nodemailer';

const HOST = process.env.SMTP_HOST;
const PORT = Number(process.env.SMTP_PORT ?? 587);
const USER = process.env.SMTP_USER;
const PASS = process.env.SMTP_PASS;
const FROM = process.env.SMTP_FROM ?? 'CipherChat <no-reply@cipherchat.app>';

export const emailConfigured = !!(HOST && USER && PASS);

const transport = emailConfigured
  ? nodemailer.createTransport({
      host: HOST,
      port: PORT,
      secure: PORT === 465,
      auth: { user: USER, pass: PASS },
    })
  : null;

export async function sendCode(to, purpose, code) {
  const label = purpose === 'verify' ? 'verification' : 'password reset';
  const subject = `Your CipherChat ${label} code`;
  const text =
    `Your CipherChat ${label} code is: ${code}\n\n` +
    `It expires in 15 minutes. If you did not request this, ignore this email.`;
  if (!emailConfigured) {
    console.log(`[email:dev] to=${to} purpose=${purpose} code=${code}`);
    return;
  }
  await transport.sendMail({ from: FROM, to, subject, text });
}
