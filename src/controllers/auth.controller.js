import User from "../models/user.model.js";
import { signupSchema } from "../validations/auth.validation.js";
import { loginSchema } from "../validations/auth.validation.js";
import {
	generateAccessToken,
	generateRefreshToken,
} from "../utils/jwt.utils.js";
import crypto from "crypto";
import { sendEmail } from "../utils/sendEmail.js";

/**
 * @route   POST /api/auth/signup
 * @desc    Register new user
 */
export const signup = async (req, res) => {
	try {
		// Validate input using zod
		const parsed = signupSchema.safeParse(req.body);
		if (!parsed.success) {
			return res.status(400).json({ error: parsed.error.errors[0].message });
		}

		// Extract from parsed object (validated data)
		const { name, email, password } = parsed.data;

		// Check if email already exists
		const existingUser = await User.findOne({ email });

		if (existingUser) {
			return res.status(409).json({ error: "Email already in use" });
		}

		// Create user (password is hashed in model)
		const user = await User.create({ name, email, password });

		// In real-world, send email verification here
		return res.status(201).json({
			message: "User registered successfully",
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
			},
		});
	} catch (error) {
		console.error("Signup error:", error);
		return res.status(500).json({ error: "Server error" });
	}
};

/**
 * @route   POST /api/auth/login
 * @desc    Login user & return JWT tokens
 */

export const login = async (req, res) => {
	try {
		// Validate login input
		const parsed = loginSchema.safeParse(req.body);
		if (!parsed.success) {
			return res.status(400).json({ error: parsed.error.errors[0].message });
		}

		const { email, password } = parsed.data;

		// Find user via email
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(401).json({ error: "Invalid email or password" });
		}

		// Compare passwords using bcrypt
		const isMatch = await user.comparePassword(password);
		if (!isMatch) {
			return res.status(401).json({ error: "Invalid email or password" });
		}

		// Generate tokens
		const accessToken = generateAccessToken(user);
		const refreshToken = generateRefreshToken(user);

		// Return tokens and user info
		return res.status(200).json({
			message: "Login successful",
			user: {
				id: user._id,
				name: user.name,
				email: user.email,
			},
			accessToken,
			refreshToken,
		});
	} catch (error) {
		console.log("Login error:", error);
		return res.status(500).json({ error: "Server error" });
	}
};

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Send password reset email
 */
export const forgotPassword = async (req, res) => {
	const { email } = req.body;
	try {
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(404).json({ error: "User not found" });
		}

		const resetToken = user.generatePasswordResetToken();
		await user.save({ validateBeforeSave: false });

		// Frontend link
		const resetURL = `http://localhost:5173/reset-password/${resetToken}`;
		const message = `Reset your password by clicking this link:\n\n${resetURL}\n\nThis link expires in 15 minutes.`;

		await sendEmail({
			to: user.email,
			subject: "Password Reset Request",
			text: message,
		});

		return res.status(200).json({ message: "Reset email sent successfully" });
	} catch (error) {
		console.error("Forgot password error:", error);
		return res.status(500).json({ error: "Email could not be sent" });
	}
};

/**
 * @route   POST /api/auth/reset-password/:token
 * @desc    Reset password using token
 */
export const resetPassword = async (req, res) => {
	const { token } = req.params;
	const { password } = req.body;

	const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

	try {
		const user = await User.findOne({
			resetPasswordToken: hashedToken,
			resetPasswordExpire: { $gt: Date.now() }, // check expiry
		});

		if (!user) {
			return res.status(400).json({ error: "Token is invalid or has expired" });
		}

		user.password = password;
		user.resetPasswordToken = undefined;
		user.resetPasswordExpire = undefined;
		await user.save();

		return res.status(200).json({ message: "Password reset successful" });
	} catch (error) {
		console.error("Reset password error:", error);
		return res.status(500).json({ error: "Something went wrong" });
	}
};
