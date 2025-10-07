import { ApiError } from "../utils/ApiError.utils.js";
import jwt from "jsonwebtoken";
import { User } from "../models/users.models.js";
import { asyncHandler } from "../utils/asyncHandler.utils.js";

export const authMiddleware = asyncHandler(async (req, _, next) => {
  try {
    const token = req.header("Authorization")?.replace("Bearer ", "") 
    console.log("Token from Auth Middleware:", token);

    if (!token) {
      throw new ApiError(401, "No token provided");
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken -__v"
    );

    if (!user) {
      throw new ApiError(404, "User not found");
    }

    req.user = user;
    next();
  } catch (error) {
    // Log original error for debugging
    console.error("Auth Middleware Error:", error);

    // Provide more specific messages for common JWT errors
    if (error.name === "TokenExpiredError") {
      throw new ApiError(401, "Token expired", error.message);
    }

    if (error.name === "JsonWebTokenError") {
      throw new ApiError(401, "Invalid token", error.message);
    }

    // Fallback generic unauthorized message
    throw new ApiError(
      401,
      "Not authorized to access this resource",
      error?.message
    );
  }
});
