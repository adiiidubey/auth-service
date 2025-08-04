import dotenv from "dotenv";
import app from "./src/app.js";
import { connectDB } from "./src/config/db.js";

dotenv.config();

const PORT = process.env.PORT || 5000;

// Connect DB then start server
connectDB().then(() => {
	app.listen(PORT, () => {
		console.log(`Server is running on ${PORT}`);
	});
});
