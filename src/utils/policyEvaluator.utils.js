/**
 * 🧠 Policy Evaluator Utility
 * Evaluates ABAC (Attribute-Based Access Control) conditions dynamically
 * Supports complex attribute comparisons like Azure's policy engine
 */

/**
 * Evaluate a single condition
 * @param {Object} condition - The condition object with attribute, operator, and value
 * @param {Object} context - The context object containing user, resource, and environment data
 * @returns {boolean} - Whether the condition is satisfied
 */
const evaluateCondition = (condition, context) => {
  const { attribute, operator, value } = condition;

  // Extract the actual value from context using dot notation
  const actualValue = getNestedValue(context, attribute);

  switch (operator) {
    case "==":
    case "equals":
      return actualValue === value;

    case "!=":
    case "notEquals":
      return actualValue !== value;

    case ">":
    case "greaterThan":
      return actualValue > value;

    case ">=":
    case "greaterThanOrEqual":
      return actualValue >= value;

    case "<":
    case "lessThan":
      return actualValue < value;

    case "<=":
    case "lessThanOrEqual":
      return actualValue <= value;

    case "in":
    case "contains":
      return Array.isArray(value) ? value.includes(actualValue) : false;

    case "notIn":
    case "notContains":
      return Array.isArray(value) ? !value.includes(actualValue) : true;

    case "startsWith":
      return typeof actualValue === "string" && actualValue.startsWith(value);

    case "endsWith":
      return typeof actualValue === "string" && actualValue.endsWith(value);

    case "matches":
    case "regex":
      return new RegExp(value).test(actualValue);

    case "inRange":
      // For time ranges or numeric ranges
      if (Array.isArray(value) && value.length === 2) {
        return actualValue >= value[0] && actualValue <= value[1];
      }
      return false;

    case "outRange":
      // Outside of range
      if (Array.isArray(value) && value.length === 2) {
        return actualValue < value[0] || actualValue > value[1];
      }
      return false;

    case "exists":
      return actualValue !== undefined && actualValue !== null;

    case "notExists":
      return actualValue === undefined || actualValue === null;

    default:
      console.warn(`Unknown operator: ${operator}`);
      return false;
  }
};

/**
 * Get nested value from object using dot notation
 * @param {Object} obj - The object to search
 * @param {string} path - The path in dot notation (e.g., "user.department")
 * @returns {*} - The value at the path
 */
const getNestedValue = (obj, path) => {
  return path.split(".").reduce((current, key) => {
    return current?.[key];
  }, obj);
};

/**
 * Evaluate all conditions in a policy
 * @param {Array} conditions - Array of condition objects
 * @param {Object} context - The context object
 * @param {string} logic - "AND" or "OR" logic for combining conditions
 * @returns {boolean} - Whether all/any conditions are satisfied
 */
export const evaluatePolicy = (conditions, context, logic = "AND") => {
  if (!Array.isArray(conditions) || conditions.length === 0) {
    return true; // No conditions means allow by default
  }

  if (logic === "OR") {
    // At least one condition must be true
    return conditions.some((condition) =>
      evaluateCondition(condition, context)
    );
  } else {
    // All conditions must be true (AND logic)
    return conditions.every((condition) =>
      evaluateCondition(condition, context)
    );
  }
};

/**
 * Build context object from request and user data
 * @param {Object} req - Express request object
 * @param {Object} user - User object from database
 * @param {Object} resource - Resource object (optional)
 * @returns {Object} - Context object for policy evaluation
 */
export const buildContext = (req, user, resource = null) => {
  const now = new Date();

  return {
    user: {
      _id: user._id?.toString(),
      username: user.username,
      email: user.email,
      role: user.role?.name || user.role,
      department: user.department,
      location: user.location,
      isActive: user.isActive,
    },
    resource: resource
      ? {
          _id: resource._id?.toString(),
          name: resource.name,
          type: resource.type,
          sensitivity: resource.sensitivity,
          department: resource.department,
          owner: resource.owner?.toString(),
        }
      : null,
    environment: {
      time: now.toTimeString().slice(0, 5), // "HH:MM"
      date: now.toISOString().split("T")[0], // "YYYY-MM-DD"
      timestamp: now.getTime(),
      dayOfWeek: now.getDay(), // 0-6 (Sunday-Saturday)
      hour: now.getHours(),
      ip: req.ip || req.connection?.remoteAddress,
      userAgent: req.get("user-agent"),
      method: req.method,
      path: req.path,
    },
    request: {
      method: req.method,
      path: req.path,
      params: req.params,
      query: req.query,
    },
  };
};

/**
 * Evaluate ABAC conditions for simple object-based conditions
 * (Used in abac.middleware.js for simpler condition objects)
 * @param {Object} conditions - Conditions object (e.g., { ownResource: true, department: "IT" })
 * @param {Object} req - Express request object
 * @param {Object} user - User object
 * @returns {boolean} - Whether conditions are satisfied
 */
export const evaluateSimpleConditions = (conditions, req, user) => {
  if (!conditions || Object.keys(conditions).length === 0) {
    return true; // No conditions means allow
  }

  // Check ownResource condition
  if (conditions.ownResource && req.params?.id !== String(user._id)) {
    return false;
  }

  // Check department condition
  if (conditions.department && conditions.department !== user.department) {
    return false;
  }

  // Check location condition
  if (conditions.location && conditions.location !== user.location) {
    return false;
  }

  // Check any other custom conditions
  for (const [key, value] of Object.entries(conditions)) {
    if (["ownResource", "department", "location"].includes(key)) {
      continue; // Already handled above
    }

    // Generic comparison for other conditions
    if (user[key] !== value) {
      return false;
    }
  }

  return true;
};

/**
 * Check if current time is within working hours
 * @param {string} startTime - Start time in "HH:MM" format
 * @param {string} endTime - End time in "HH:MM" format
 * @returns {boolean} - Whether current time is within range
 */
export const isWithinWorkingHours = (
  startTime = "09:00",
  endTime = "18:00"
) => {
  const now = new Date();
  const currentTime = now.toTimeString().slice(0, 5);

  return currentTime >= startTime && currentTime <= endTime;
};

/**
 * Check if current day is a working day
 * @param {Array<number>} workingDays - Array of working days (0-6, Sunday-Saturday)
 * @returns {boolean} - Whether today is a working day
 */
export const isWorkingDay = (workingDays = [1, 2, 3, 4, 5]) => {
  const today = new Date().getDay();
  return workingDays.includes(today);
};

/**
 * Evaluate complex policy with multiple conditions and logic
 * @param {Object} policy - Policy object with conditions array
 * @param {Object} context - Context object
 * @returns {Object} - Result with allowed status and reason
 */
export const evaluateComplexPolicy = (policy, context) => {
  try {
    const { conditions, effect, logic = "AND" } = policy;

    const conditionsMet = evaluatePolicy(conditions, context, logic);

    if (effect === "deny") {
      // Deny policy: if conditions met, access is denied
      return {
        allowed: !conditionsMet,
        reason: conditionsMet
          ? "Policy explicitly denies access"
          : "Deny conditions not met",
        policy: policy.name || "unnamed",
      };
    } else {
      // Allow policy: if conditions met, access is allowed
      return {
        allowed: conditionsMet,
        reason: conditionsMet
          ? "Policy allows access"
          : "Allow conditions not met",
        policy: policy.name || "unnamed",
      };
    }
  } catch (error) {
    console.error("Error evaluating policy:", error);
    return {
      allowed: false,
      reason: "Error evaluating policy",
      error: error.message,
    };
  }
};

export default {
  evaluatePolicy,
  evaluateCondition,
  buildContext,
  evaluateSimpleConditions,
  evaluateComplexPolicy,
  isWithinWorkingHours,
  isWorkingDay,
  getNestedValue,
};
