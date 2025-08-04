import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || "1h";
const REFRESH_EXPIRES_IN = process.env.JWT_REFRESH_EXPIRES_IN || "7d";

// Generate access token
export const generateAccessToken = (user) => {
	return jwt.sign(
		{
			id: user._id,
			email: user.email,
		},
		JWT_SECRET,
		{ expiresIn: JWT_EXPIRES_IN }
	);
};

// Generate refresh token
export const generateRefreshToken = (user) => {
	return jwt.sign(
		{
			user: user._id,
		},
		JWT_SECRET,
		{ expiresIn: JWT_EXPIRES_IN }
	);
};
