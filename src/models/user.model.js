import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const userSchema = new mongoose.Schema(
	{
		name: {
			type: String,
			required: true,
			trim: true,
		},

		email: {
			type: String,
			required: true,
			unique: true,
			lowercase: true,
			trim: true,
		},

		password: {
			type: String,
			required: true,
			minlength: 6,
		},

		isVerified: {
			type: Boolean,
			default: false,
		},

		resetPasswordToken: String,
		resetPasswordExpire: Date,
	},
	{ timestamps: true }
);

// Encrypt password before saving user
userSchema.pre("save", async function (next) {
	// skip if not modified
	if (!this.isModified("password")) return next();
	this.password = await bcrypt.hash(this.password, 10);
	next();
});

// Compare password for login
userSchema.methods.comparePassword = async function (candidatePassword) {
	return await bcrypt.compare(candidatePassword, this.password);
};

// Generate password reset token
userSchema.methods.generatePasswordResetToken = function () {
	// Generate raw token
	const resetToken = crypto.randomBytes(32).toString("hex");

	// Hash and store in DB (never store raw token)
	this.resetPasswordToken = crypto
		.createHash("sha256")
		.update(resetToken)
		.digest("hex");

	// Set expiry (15 min)
	this.resetPasswordToken = Date.now() + 15 * 60 * 1000;

	return resetToken;
};

const User = mongoose.model("User", userSchema);

export default User;
