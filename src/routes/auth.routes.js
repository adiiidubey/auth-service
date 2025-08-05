import express from "express";
import { signup, login, forgotPassword, resetPassword } from "../controllers/auth.controller.js";

const router = express.Router();

// auth routes
router.post("/signup", signup);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

export default router;