const mongoose = require("mongoose");
const validator = require("validator");
const bcrypt = require("bcryptjs");

const UserSchema = new mongoose.Schema(
	{
		name: {
			type: String,
			required: [true, "Please Enter Your Fucking Name"],
			minLength: [3, "Name must be atleast 3 characters long"],
			maxLength: [50, "Name cannot be longer than 50 characters"],
			trim: true,
		},
		email: {
			type: String,
			required: [true, "Please Enter Your Fucking Email"],
			unique: [true, "This email is already taken"],
			validate: {
				validator: validator.isEmail,
				message: "Please provide a valid email",
			},
		},
		password: {
			type: String,
			required: [true, "Please Enter a Password"],
			minLength: [6, "Password must be atleast 6 characters long"],
		},
		role: {
			type: String,
			enum: ["admin", "user"],
			default: "user",
		},
		isVerified: {
			type: Boolean,
			default: false,
		},
		verificationToken: String,
		verified: Date,
		passwordToken: String,
		passwordTokenExpirarionDate: Date,
	},
	{ timestamps: true }
);

UserSchema.pre("save", async function () {
	const salt = await bcrypt.genSalt(10);
	this.password = await bcrypt.hash(this.password, salt);
});

UserSchema.methods = {
	comparePasswords: async function (candidatePassword) {
		return await bcrypt.compare(candidatePassword, this.password);
	},
};

module.exports = mongoose.model("User", UserSchema);
