import nodemailer from 'nodemailer'

// We need SMTP(Simple Mail Transfer Protocol) details to send a mail, to 
const transporter = nodemailer.createTransport({
  host: 'smtp-relay.brevo.com',
  port: 587,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  }
})

export default transporter;