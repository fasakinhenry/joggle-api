const { Resend } = require('resend');

const resend = new Resend(process.env.RESEND_API_KEY);

const sendVerificationEmail = async (email, verificationToken) => {
  const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${verificationToken}`;

  try {
    await resend.emails.send({
      from: 'onboarding@resend.dev', // Replace with your verified domain or use 'onboarding@resend.dev' for testing
      to: email,
      subject: 'Verify Your Email',
      html: `
        <h4>Please verify your email</h4>
        <p>Click <a href="${verificationUrl}">here</a> to verify your email address.</p>
      `,
    });
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error('Error sending verification email:', error);
    throw new Error('Failed to send verification email');
  }
};

module.exports = { sendVerificationEmail };
