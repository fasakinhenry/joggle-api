const { Resend } = require('@resend/resend');

const resend = new Resend(process.env.RESEND_API_KEY);

const sendVerificationEmail = async (
  email,
  token,
  subject = 'Verify Your Email',
  htmlContent
) => {
  const url = subject.includes('Password')
    ? `${process.env.FRONTEND_URL}/reset-password?token=${token}`
    : `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
  try {
    await resend.emails.send({
      from: 'no-reply@your-elearning-app.com',
      to: email,
      subject,
      html:
        htmlContent ||
        `
        <h4>${subject}</h4>
        <p>Click <a href="${url}">here</a> to ${subject.toLowerCase()}. ${subject.includes('Password') ? 'This link expires in 1 hour.' : ''}</p>
      `,
    });
    console.log(`Email sent to ${email}`);
  } catch (error) {
    console.error('Error sending email:', error);
    throw new Error('Failed to send email');
  }
};

module.exports = { sendVerificationEmail };
