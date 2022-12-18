const { StatusCodes } = require("http-status-codes");
const crypto = require("crypto");
const User = require("../models/User");
const Token = require("../models/Token");
const CustomError = require("../errors");
const {
	attachCookiesToResponse,
	createTokenUser,
	sendEmail,
	createHash,
} = require("../utils");

const registerUser = async (req, res) => {
	const { name, email, password } = req.body;
	// checking whether the email is unique inside the controller
	if (await User.findOne({ email })) {
		throw new CustomError.BadRequestError("Email already exists");
	}
	// code to detect if a farzi email is entered
	// const { valid } = await isEmailValid(email);
	// if (!valid) {
	// 	throw new CustomError.BadRequestError("Inactive email");
	// }
	// register first user as admin
	const role = (await User.countDocuments({})) === 0 ? "admin" : "user";
	const verificationToken = crypto.randomBytes(40).toString("hex");
	await User.create({
		name,
		email,
		password,
		role,
		verificationToken,
	});
	// change this url according to your front-end routing
	const verifyEmail = `${process.env.CLIENT_URL}/user/verify-email?token=${verificationToken}&email=${email}`;
	// sending verification email
	await sendEmail({
		email: email,
		subject: `Hi ${name}, Verify Your Account`,
		html: `
		<p>In order to verify your account please click on the link given below</p>
		<a href="${verifyEmail}"><button>Verify Email</button></a> 
		`,
	});
	res.status(StatusCodes.CREATED).json({
		message: "Success! Please check your email to verify account",
	});
};

const verifiyEmail = async (req, res) => {
	const { verificationToken, email } = req.body;
	const user = User.findOne({ email });
	if (!user) {
		throw new CustomError.UnauthenticatedError("verification failed");
	}
	if (user.verificationToken !== verificationToken) {
		throw new CustomError.UnauthenticatedError("verification failed");
	}
	user.isVerified = true;
	user.verified = Date.now();
	user.verificationToken = "";
	await user.save();
	res.status(StatusCodes.OK).json({ message: "Email Verified" });
};

const loginUser = async (req, res) => {
	const { email, password } = req.body;
	if (!email || !password) {
		throw new CustomError.BadRequestError("Please provide email and password");
	}
	const user = await User.findOne({ email });
	if (!user) {
		throw new CustomError.UnauthenticatedError("Invalid Credentials");
	}
	if (!(await user.comparePasswords(password))) {
		throw new CustomError.UnauthenticatedError("Invalid Credentials");
	}
	if (!user.isVerified) {
		throw new CustomError.UnauthenticatedError("Please Verify Your Email");
	}
	const tokenUser = createTokenUser(user);
	// create refresh token
	let refreshToken = "";
	// check for existing token
	const existingToken = await Token.findOne({ user: user._id });
	if (existingToken) {
		const { isValid } = existingToken;
		if (!isValid) {
			throw new CustomError.UnauthenticatedError("Invalid Credentials");
		}
		refreshToken = existingToken.refreshToken;
		attachCookiesToResponse({ res, user: tokenUser, refreshToken });
		res.status(StatusCodes.OK).json({ user: tokenUser });
		return;
	}
	refreshToken = crypto.randomBytes(40).toString("hex");
	const userToken = {
		refreshToken,
		ip: req.ip,
		userAgent: req.headers["user-agent"],
		user: user._id,
	};
	await Token.create(userToken);
	attachCookiesToResponse({ res, user: tokenUser, refreshToken });
	res.status(StatusCodes.OK).json({ user: tokenUser });
};

const logoutUser = async (req, res) => {
	await Token.findOneAndDelete({ user: req.user.userId });
	res.cookie("accessToken", "logout", {
		httpOnly: true,
		expires: new Date(Date.now()),
	});
	res.cookie("refreshToken", "logout", {
		httpOnly: true,
		expires: new Date(Date.now()),
	});
	res.status(StatusCodes.OK).json({ message: "User Logged Out!" });
};

const forgotPassword = async (req, res) => {
	const { email } = req.body;
	if (!email) {
		throw new CustomError.BadRequestError("Please provide valid email");
	}
	const user = await User.findOne({ email: email });
	if (user) {
		const passwordToken = crypto.randomBytes(40).toString("hex");
		// change this url according to your front-end routing
		const resetPassword = `${process.env.CLIENT_URL}/user/reset-password?token=${passwordToken}&email=${email}`;
		// sending verification email
		await sendEmail({
			email: user.email,
			subject: `Hi ${user.name}, Reset Your Password`,
			html: `
		<p>In order to reset your current password please click on the link given below</p>
		<a href="${resetPassword}"><button>Reset Password</button></a> 
		`,
		});
		user.passwordToken = createHash(passwordToken);
		user.passwordTokenExpires = Date.now() + 600000; // 10 minutes expiration
		await user.save();
	}
	res
		.status(StatusCodes.OK)
		.json({ message: "Please Check Your Email For Reset Password Link" });
};

const resetPassword = async (req, res) => {
	const { token, email, password } = req.body;
	if (!token || !email || !password) {
		throw new CustomError.BadRequestError(
			"Please Provide All The Valid Details"
		);
	}
	const user = await User.findOne({ email });
	if (user) {
		if (
			user.passwordToken == createHash(token) &&
			user.passwordTokenExpirarionDate > new Date()
		) {
			user.password = password;
			user.passwordToken = "";
			user.passwordTokenExpirarionDate = "";
			await user.save();
		}
	}
	res.status(StatusCodes.OK).json({ message: "Password Reset Successfully" });
};

const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const googleLogin = async (req, res) => {
	const {idToken}=req.body
	await client
		.verifyIdToken({ idToken, audience: process.env.GOOGLE_CLIENT_ID })
		.then((response) => {
			const { email_verified, name, email } = response.payload;
			if (email_verified) {
				User.findOne({ email }).exec((err, user) => {
					if (user) {
						const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, {
							expiresIn: "7d",
						});
						const { _id, email, name, role } = user;
						return res.json({
							token,
							user: { _id, email, name, role },
						});
					} else {
						let password = email + process.env.JWT_SECRET;
						user = new User({ name, email, password });
						user.save((err, data) => {
							if (err) {
								console.log("ERROR GOOGLE LOGIN ON USER SAVE", err);
								return res.status(400).json({
									error: "User signup failed with google",
								});
							}
							const token = jwt.sign(
								{ _id: data._id },
								process.env.JWT_SECRET,
								{
									expiresIn: "7d",
								}
							);
							const { _id, email, name, role } = data;
							return res.json({
								token,
								user: { _id, email, name, role },
							});
						});
					}
				});
			} else {
				return res.status(400).json({
					error: "Google login failed. Try again",
				});
			}
		});
}

module.exports = {
	registerUser,
	verifiyEmail,
	loginUser,
	logoutUser,
	forgotPassword,
	resetPassword,
	googleLogin,
};
