const {
	getAllUsers,
	getSingleUser,
	updateUserPassword,
	updateUser,
	showCurrentUser,
} = require("../controllers/userController");

const {
	authenticateUser,
	authorizePermissions,
} = require("../middleware/authentication");

const router = require("express").Router();

router
	.route("/")
	.get(authenticateUser, authorizePermissions("admin"), getAllUsers);
router.route("/show-me").get(authenticateUser, showCurrentUser);
router
	.route("/update-user-password")
	.patch(authenticateUser, updateUserPassword);
router.route("/update-user").patch(authenticateUser, updateUser);
router.route("/:id").get(authenticateUser, getSingleUser);

module.exports = router;
