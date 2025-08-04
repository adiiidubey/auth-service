import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import authRoutes from "./routes/auth.routes.js";

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());

// Rate Limiter
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 100, // max requests per 15 min
});
app.use(limiter);

app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
	res.send("Auth Service Running...");
});

export default app;
