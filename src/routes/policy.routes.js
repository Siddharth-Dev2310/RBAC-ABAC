import { Router } from "express";
import { authMiddleware } from "../middleware/auth.middleware.js";
import { rbacMiddleware } from "../middleware/rbac.middleware.js";
import {
getAllPolicies,
getPolicyById,
createPolicy,
updatePolicy,
deletePolicy,
togglePolicyStatus,
getPoliciesByRole,
getPoliciesByAction,
} from "../controller/policy.controller.js";

const router = Router();

// Apply authentication middleware to all routes
router.use(authMiddleware);

// 📋 Get all policies (with filtering)
router.get(
"/",
rbacMiddleware(["admin", "superadmin"]),
getAllPolicies
);

// 📊 Get policies by role
router.get(
"/role/:roleId",
rbacMiddleware(["admin", "superadmin"]),
getPoliciesByRole
);

// 📊 Get policies by action
router.get(
"/action/:action",
rbacMiddleware(["admin", "superadmin"]),
getPoliciesByAction
);

// 🔍 Get policy by ID
router.get(
"/:id",
rbacMiddleware(["admin", "superadmin"]),
getPolicyById
);

// ➕ Create new policy
router.post(
"/create",
rbacMiddleware(["admin", "superadmin"]),
createPolicy
);

// ✏️ Update policy
router.put(
"/:id",
rbacMiddleware(["admin", "superadmin"]),
updatePolicy
);

// 🔄 Toggle policy status
router.patch(
"/:id/toggle",
rbacMiddleware(["admin", "superadmin"]),
togglePolicyStatus
);

// 🗑️ Delete policy (SuperAdmin only)
router.delete(
"/:id",
rbacMiddleware(["superadmin"]),
deletePolicy
);

export default router;