const { StatusCodes } = require("http-status-codes");
const User = require("../models/User");
const CustomError = require("../errors");
const {
	attachCookiesToResponse,
	createTokenUser,
	checkPermissions,
} = require("../utils");

const getAllUsers = async (req, res) => {
	const users = await User.find({}).select("-password");
	res.status(StatusCodes.OK).json({ users });
};

const getSingleUser = async (req, res) => {
	const { id } = req.params;
	const user = await User.findById(id).select("-password");
	if (!user) {
		throw new CustomError.NotFoundError(`No user with id ${id}`);
	}
	checkPermissions(req.user, user._id);
	res.status(StatusCodes.OK).json({ user });
};

const showCurrentUser = async (req, res) => {
	res.status(StatusCodes.OK).json({ user: req.user });
};

const updateUserPassword = async (req, res) => {
	const { oldPassword, newPassword } = req.body;
	if (!newPassword || !oldPassword) {
		throw new CustomError.BadRequestError("Please Enter Both Values");
	}
	const user = await User.findById(req.user.userId);
	if (oldPassword === (await user.comparePasswords(oldPassword))) {
		throw new CustomError.UnauthenticatedError("Invalid Credentials");
	}
	user.password = newPassword;
	await user.save();
	res.status(StatusCodes.OK).json({ message: "Password Changed Sucessfully" });
};

const updateUser = async (req, res) => {
	const { email, name } = req.body;
	if (!email || !name) {
		throw new CustomError.BadRequestError("Please provide all value");
	}
	const user = await User.findByIdAndUpdate(
		req.user.userId,
		{ name, email },
		{ new: true, runValidators: true }
	);
	const tokenUser = createTokenUser(user);
	attachCookiesToResponse({ res, user: tokenUser });
	res.status(StatusCodes.OK).json({ user: tokenUser });
};

module.exports = {
	getAllUsers,
	getSingleUser,
	showCurrentUser,
	updateUser,
	updateUserPassword,
};
