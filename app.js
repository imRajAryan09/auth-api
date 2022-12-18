require("dotenv").config();
require("express-async-errors");
const express = require("express");
const app = express();

// rest of packages
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const rateLimiter = require("express-rate-limit");
const helmet = require("helmet");
const xss = require("xss-clean");
const mongoSanitize = require("express-mongo-sanitize");

// database
const connectDB = require("./db/connect");

// import routes
const authRouter = require("./routes/authRoutes");
const userRouter = require("./routes/userRoutes");

// middleware

const errorHandlerMiddleware = require("./middleware/error-handler");
const notFound = require("./middleware/not-found");

// middleware
app.set("trust proxy", 1);
app.use(
	rateLimiter({
		windowMs: 15 * 60 * 1000,
		max: 60,
	})
);
app.use(helmet());
app.use(cors());
app.use(xss());
app.use(mongoSanitize());
app.use(morgan("common"));
app.use(express.json());
app.use(cookieParser(process.env.JWT_SECRET));

app.get("/api/v1", (req, res) => {
	res.send("E-commerce API");
});

app.use("/api/v1/auth", authRouter);
app.use("/api/v1/users", userRouter);

app.use(notFound);
app.use(errorHandlerMiddleware);

// port
const PORT = process.env.PORT || 5000;

const start = async () => {
	try {
		await connectDB(process.env.MONGO_URI);
		app.listen(PORT, () => console.log(`server is running on ${PORT}`));
	} catch (error) {
		console.log("ERROR IN STARTING THE SERVER");
	}
};

start();
