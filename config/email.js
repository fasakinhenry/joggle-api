const { Resend } = require('resend');
const logger = require('./logger');

const resend = new Resend(process.env.RESEND_API_KEY);

const sendEmail = async (to, subject, html) => {
  try {
    const data = await resend.emails.send({
      from: 'no-reply@yourdomain.com',
      to,
      subject,
      html,
    });
    logger.info(`Email sent to ${to}: ${data.id}`);
    return data;
  } catch (error) {
    logger.error(`Error sending email to ${to}:`, error);
    throw error;
  }
};

module.exports = { sendEmail };
