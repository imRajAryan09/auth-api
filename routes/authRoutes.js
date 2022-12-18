const {
	registerUser,
	loginUser,
	logoutUser,
	verifiyEmail,
	resetPassword,
	forgotPassword,
	googleLogin,
} = require("../controllers/authController");
const { authenticateUser } = require("../middleware/authentication");

const router = require("express").Router();

router.route("/register").post(registerUser);
router.route("/verify-email").post(verifiyEmail);
router.route("/reset-password").post(resetPassword);
router.route("/forgot-password").post(forgotPassword);
router.route("/login").post(loginUser);
router.route("/logout").delete(authenticateUser, logoutUser);
router.post("/login/google", googleLogin);


module.exports = router;
