import { Router } from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { rbacMiddleware } from "../middleware/rbac.middleware.js";
import { abacMiddleware } from "../middleware/abac.middleware.js";
import {
  createUser,
  getUserById,
  getAllUsers,
  updateUser,
} from "../controller/user.controller.js";

const router = Router();

/**
 * @route   GET /api/users
 * @desc    Get all users
 * @access  Admin, SuperAdmin (RBAC)
 */
router.get(
  "/",
  authMiddleware,
  rbacMiddleware(["admin", "superadmin"]),
  getAllUsers
);

/**
 * @route   GET /api/users/:id
 * @desc    Get user by ID
 * @access  Admin, SuperAdmin, Editor, Viewer (RBAC + ABAC: read:user)
 */
router.get(
  "/:id",
  authMiddleware,
  rbacMiddleware(["admin", "superadmin", "editor", "viewer"]),
  abacMiddleware("read:user"),
  getUserById
);

/**
 * @route   POST /api/users
 * @desc    Create new user
 * @access  Admin, SuperAdmin (RBAC + ABAC: create:user)
 */
router.post(
  "/register",
  authMiddleware,
  rbacMiddleware(["admin", "superadmin"]),
  abacMiddleware("create:user"),
  createUser
);

/**
 * @route   PUT /api/users/:id
 * @desc    Update user
 * @access  Admin, SuperAdmin (RBAC + ABAC: edit:user)
 */
router.put(
  "/:id",
  authMiddleware,
  rbacMiddleware(["admin", "superadmin"]),
  abacMiddleware("edit:user"),
  updateUser
);

export default router;
