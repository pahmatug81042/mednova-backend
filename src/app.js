const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const mongoSanitize = require("express-mongo-sanitize");
const rateLimit = require("express-rate-limit");
const morgan = require("morgan");
const dotenv = require("dotenv");

dotenv.config();

const app = express();

// High-Security Middleware
app.use(helmet({
    contentSecurityPolicy: false // Will add CSP later for reporting
}));

app.use(cors({
    origin: process.env.CLIENT_URL,
    credentials: true,
}));

app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(morgan("dev"));

// Enforce JSON-only input
app.use((req, res, next) => {
    if (req.headers["content-type"] !== "application/json" && req.method !== "GET") {
        return res.status(415).json({ message: "Content-Type must be application/json" });
    }
    next();
});

// Basic Route
app.get("/api/health", (req, res) => {
    res.status(200).json({ status: "OK", message: "MedNova API is running" });
});

export default app;