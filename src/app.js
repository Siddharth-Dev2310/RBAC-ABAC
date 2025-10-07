import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";

const app = express();

app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    credentials: true,
  }),
);

app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));

import userRoutes from "./routes/user.routes.js";
import policyRoutes from "./routes/policy.routes.js";
import authRoutes from "./routes/auth.routes.js";

app.use("/api/v1/auth", authRoutes);

app.use("/api/v1/users", userRoutes);
app.use("/api/v1/policies", policyRoutes);

export { app };
