const CustomError = require("../errors");

exports.checkPermissions = (requestUser, resourceUserId) => {
	if (requestUser.role === "admin") return;
	if (requestUser.userId === resourceUserId.toString()) return;
	throw new CustomError.UnauthorizedError(
		"Not authorized to access this route"
	);
};
