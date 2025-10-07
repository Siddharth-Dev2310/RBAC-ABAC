import { ApiError } from "../utils/ApiError.utils.js";
import { asyncHandler } from "../utils/asyncHandler.utils.js";
import { Policy } from "../models/policy.models.js";
import {
  evaluateSimpleConditions,
  evaluateComplexPolicy,
  buildContext,
} from "../utils/policyEvaluator.utils.js";

/**
 * ABAC Middleware: Check if the user meets attribute-based policy conditions
 * @param {string} action - The action name (e.g., "read:user", "edit:project")
 */
export const abacMiddleware = (action) =>
  asyncHandler(async (req, _, next) => {
    const user = req.user;

    console.log(
      `Action: ${action}, User Role: ${user.role}, Department: ${user.department}`
    );

    // Fetch all policies related to the user's role and action
    const policies = await Policy.find({
      role: { $in: [user.role] }, // Check if user's role is in the policy's role array
      action,
      isActive: true,
    });

    if (!policies || policies.length === 0) {
      throw new ApiError(403, "No policy found for this action");
    }

    // Evaluate conditions dynamically
    const allowed = policies.some((policy) => {
      const conditions = policy.conditions || {};

      // If no conditions, allow access
      if (Object.keys(conditions).length === 0) {
        return true;
      }

      // Check if conditions is an array (complex policy) or object (simple policy)
      if (Array.isArray(conditions)) {
        // Use advanced policy evaluator for complex conditions
        const context = buildContext(req, user);
        const result = evaluateComplexPolicy(
          { conditions, effect: policy.effect || "allow" },
          context
        );
        return result.allowed;
      } else {
        // Use simple condition evaluation for object-based conditions
        return evaluateSimpleConditions(conditions, req, user);
      }
    });

    if (!allowed) {
      throw new ApiError(
        403,
        "ABAC policy denied access - conditions not met",
        { action, userDepartment: user.department, userLocation: user.location }
      );
    }

    next();
  });
