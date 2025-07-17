const { Resend } = require('resend');
const logger = require('./logger');

const resend = new Resend(process.env.RESEND_API_KEY);

const sendVerificationEmail = async (
  email,
  token,
  subject = 'Verify Your Email',
  htmlContent
) => {
  const url = subject.includes('Password')
    ? `${process.env.FRONTEND_URL}/auth/reset-password?token=${token}`
    : `${process.env.FRONTEND_URL}/auth/verify-email?token=${token}`;
  try {
    const { data, error } = await resend.emails.send({
      from: 'Henqsoft <onboarding@resend.dev>',
      to: email,
      subject,
      html:
        htmlContent ||
        `
        <h4>${subject}</h4>
        <p>Welcome to Joggle, your gateway to in-demand tech skills!</p>
        <p>Click <a href="${url}">here</a> to ${subject.toLowerCase()}. ${
          subject.includes('Password') ? 'This link expires in 1 hour.' : ''
        }</p>
        <p>Ready to earn your Nova Explorer badge? Start your journey now!</p>
      `,
    });

    if (error) {
      console.error('Resend API error:', error);
      throw new Error(`Failed to send email: ${error.message}`);
    }

    console.log(`Email sent to ${email}:`, data);
    return data;
  } catch (error) {
    console.error('Error sending email:', error.message);
    throw new Error('Failed to send email');
  }
};

module.exports = { sendVerificationEmail };
