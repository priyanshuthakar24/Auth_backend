// Looking to send emails in production? Check out our Email API/SMTP product!
const { MailtrapClient } = require("mailtrap");
require('dotenv').config();
const TOKEN = process.env.MAILTRAP_TOKEN;

exports.mailtrapClient = new MailtrapClient({
    token: TOKEN,
    testInboxId: 2842965,
});

exports.sender = {
    email: "hello@example.com",
    name: "Mailtrap Test",
};
// const recipients = [
//     {
//         email: "pinkugames2401@gmail.com",
//     }
// ];

// client.testing
//     .send({
//         from: sender,
//         to: recipients,
//         subject: "You are awesome!",
//         text: "Congrats for sending test email with Mailtrap!",
//         category: "Integration Test",
//     })
//     .then(console.log, console.error);