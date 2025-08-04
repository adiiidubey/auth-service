import { z } from "zod";

// Schema for signup input validation
export const signupSchema = z.object({
	name: z.string().min(1, "Name is required"),
	email: z.string().email("Invalid email address"),
	password: z.string().min(6, "Password must be at least 6 characters"),
});

// Schema for login input validation
export const loginSchema = z.object({
	email: z.string().email("Email is required"),
	password: z.string().min(6, "Password is required"),
});
