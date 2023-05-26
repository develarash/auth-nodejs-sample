const nodemailer = require("nodemailer");
// create Email transporter
const sendEmail = async (subject, message, sent_to, sent_from, reply_to) => {
  const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: 587,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
    tls: {
      rejectUnauthorized: false,
    },
  });
  //   option for sending email
  const options = {
    from: sent_from,
    to: sent_to,
    replyTo: reply_to,
    subject: subject,
    html: message,
  };

  transporter.sendMail(options, function (err, info) {
    if (err) {
      console.log(err);
    }
    console.log(info);
  });
};

module.exports = sendEmail;
