import { ApiError } from "../utils/ApiError.utils.js";
import { Role } from "../models/role.models.js";
import { asyncHandler } from "../utils/asyncHandler.utils.js";

/**
 * RBAC Middleware: Check if the user's role has permission for an action
 * @param {string[]} allowedRoles - Array of roles allowed (e.g., ["admin", "manager"])
 */
export const rbacMiddleware = (allowedRoles = []) =>
  asyncHandler(async (req, _, next) => {
    const userRoleId = req.user?.role;

    // Allow access during user creation (registration) when no role is assigned yet
    if (!userRoleId && allowedRoles.includes("guest")) {
      return next();
    }

    if (!userRoleId) {
      throw new ApiError(403, "User role not found");
    }

    const role = await Role.findById(userRoleId);

    if (!role) {
      throw new ApiError(403, "Invalid role");
    }

    if (!allowedRoles.includes(role.name)) {
      throw new ApiError(403, `Access denied for role: ${role.name}`);
    }

    next();
  });
