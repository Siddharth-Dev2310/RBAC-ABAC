import { Router } from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { login, logout } from "../controller/auth.controller.js";

const router = Router();

/**
 * @route   POST /api/auth/login
 * @desc    User login - authenticate and get JWT tokens
 * @access  Public
 */
router.post("/login", login);

/**
 * @route   POST /api/auth/logout
 * @desc    User logout - clear refresh token
 * @access  Authenticated users
 */
router.post("/logout", authMiddleware, logout);

/**
 * @route   POST /api/auth/refresh
 * @desc    Refresh access token using refresh token
 * @access  Public (with valid refresh token)
 * @todo    Implement refresh token logic in auth.controller.js
 */
// router.post("/refresh", refreshToken);

/**
 * @route   POST /api/auth/verify
 * @desc    Verify JWT token validity
 * @access  Authenticated users
 */
router.get("/verify", authMiddleware, (req, res) => {
  res.status(200).json({
    success: true,
    message: "Token is valid",
    user: {
      id: req.user._id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role,
      department: req.user.department,
      location: req.user.location,
    },
  });
});

export default router;
