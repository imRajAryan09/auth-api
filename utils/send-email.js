const sgMail = require("@sendgrid/mail");
sgMail.setApiKey(process.env.SENDGRID_API_KEY);

const sendEmail = async ({ email, subject, html }) => {
	const emailData = {
		from: process.env.EMAIL_FROM,
		to: email,
		subject: subject,
		html: html,
	};
	return await sgMail
		.send(emailData)
		// .then((sent) => console.log(sent))
		.catch((err) => {
			console.log("SENDGRID ERROR", err);
		});
};

module.exports = { sendEmail };
