import dotenv from 'dotenv';
dotenv.config();
import nodemailer from 'nodemailer';

export const sendEmail = async (to: string, subject: string, html: string) => {
    if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASSWORD) {
        console.log('Email env are not available');
        return;
    }
    const host = process.env.SMTP_HOST;
    const port = process.env.SMTP_PORT ? parseInt(process.env.SMTP_PORT) : 587;
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASSWORD;
    const from = process.env.EMAIL_FROM
    const transporter = nodemailer.createTransport({
        host,
        port,
        secure: false,
        auth: {
            pass,
            user,
        }

    })
    await transporter.sendMail({
        from,
        to,
        subject,
        html,
    })
}