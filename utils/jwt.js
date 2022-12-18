const jwt = require("jsonwebtoken");

const createJWT = ({ payload }) => {
	const token = jwt.sign(payload, process.env.JWT_SECRET);
	return token;
};

const isTokenValid = (token) => jwt.verify(token, process.env.JWT_SECRET);

const attachCookiesToResponse = ({ res, user, refreshToken }) => {
	const acessTokenJWT = createJWT({ payload: { user } });
	const refreshTokenJWT = createJWT({ payload: { user, refreshToken } });
	res.cookie("accessToken", acessTokenJWT, {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		signed: true,
		expires: new Date(Date.now() + 86400000), // 1 day expiration
	});
	res.cookie("refreshToken", refreshTokenJWT, {
		httpOnly: true,
		secure: process.env.NODE_ENV === "production",
		signed: true,
		expires: new Date(Date.now() + 2592000000), // 30 days expiration
	});
};

module.exports = {
	createJWT,
	isTokenValid,
	attachCookiesToResponse,
};
