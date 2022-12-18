const { createJWT, isTokenValid, attachCookiesToResponse } = require("./jwt");
const { isEmailValid } = require("./active-email");
const { createTokenUser } = require("./create-token-user");
const { checkPermissions } = require("./check-permissions");
const { sendEmail } = require("./send-email");
const createHash = require("./create-hash");

module.exports = {
	createJWT,
	isTokenValid,
	isEmailValid,
	attachCookiesToResponse,
	createTokenUser,
	checkPermissions,
	sendEmail,
	createHash,
};
