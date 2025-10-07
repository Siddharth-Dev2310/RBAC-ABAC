import { Policy } from "../models/policy.models.js";
import { Role } from "../models/role.models.js";
import { ApiError } from "../utils/ApiError.utils.js";
import { ApiResponse } from "../utils/ApiResponse.utils.js";
import { asyncHandler } from "../utils/asyncHandler.utils.js";
import { logAuditEvent } from "../utils/auditLogger.utils.js";
import {
  evaluateComplexPolicy,
  buildContext,
} from "../utils/policyEvaluator.utils.js";

/**
 * 📋 Get all policies (with filtering)
 * @route GET /api/policies
 * @access Admin, SuperAdmin
 */
export const getAllPolicies = asyncHandler(async (req, res) => {
  const { role, action, effect, isActive, page = 1, limit = 20 } = req.query;

  const filter = {};
  if (role) filter.role = role;
  if (action) filter.action = action;
  if (effect) filter.effect = effect;
  if (isActive !== undefined) filter.isActive = isActive === "true";

  const skip = (page - 1) * limit;

  const policies = await Policy.find(filter)
    .populate("role", "name description")
    .populate("createdBy", "username email")
    .skip(skip)
    .limit(parseInt(limit))
    .sort({ createdAt: -1 });

  const totalPolicies = await Policy.countDocuments(filter);

  // Log audit event
  await logAuditEvent({
    userId: req.user._id,
    action: "read:policies",
    resource: "policy-list",
    status: "allowed",
    metadata: { filter, count: policies.length },
  });

  res.status(200).json(
    new ApiResponse(
      200,
      {
        policies,
        pagination: {
          currentPage: parseInt(page),
          totalPages: Math.ceil(totalPolicies / limit),
          totalPolicies,
          limit: parseInt(limit),
        },
      },
      "Policies retrieved successfully"
    )
  );
});

/**
 * 🔍 Get policy by ID
 * @route GET /api/policies/:id
 * @access Admin, SuperAdmin
 */
export const getPolicyById = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const policy = await Policy.findById(id)
    .populate("role", "name description permissions")
    .populate("createdBy", "username email");

  if (!policy) {
    throw new ApiError(404, "Policy not found");
  }

  res
    .status(200)
    .json(new ApiResponse(200, policy, "Policy retrieved successfully"));
});

/**
 * ➕ Create new policy
 * @route POST /api/policies
 * @access Admin, SuperAdmin
 */
export const createPolicy = asyncHandler(async (req, res) => {
  const { role, action, conditions, effect, isActive } = req.body;

  // Validate required fields
  if (!role || !action) {
    throw new ApiError(400, "Role and action are required");
  }

  console.log("Creating policy with data:", role, action, conditions, effect);

  // Validate role exists
  const roleExists = await Role.findOne({ name: role });

  console.log("Role exists:", roleExists);

  if (!roleExists) {
    throw new ApiError(404, "Role not found");
  }

  // Check if similar policy already exists
  const existingPolicy = await Policy.findOne({
    role: roleExists._id,
    action,
    effect: effect || "allow",
  });
  if (existingPolicy) {
    throw new ApiError(
      409,
      "A similar policy already exists for this role and action"
    );
  }

  // Create policy
  const policy = await Policy.create({
    action,
    conditions: conditions || {},
    effect: effect || "allow",
    createdBy: req.user._id,
    isActive: isActive !== undefined ? isActive : true,
  });

  // Add the role to the policy
  policy.role = roleExists._id;
  await policy.save();

  const createdPolicy = await Policy.findById(policy._id)
    .populate("role", "name description")
    .populate("createdBy", "username email");

  // Log audit event
  await logAuditEvent({
    userId: req.user._id,
    action: "create:policy",
    resource: policy._id.toString(),
    status: "allowed",
    metadata: { role: roleExists.name, action, effect },
  });

  res
    .status(201)
    .json(new ApiResponse(201, createdPolicy, "Policy created successfully"));
});

/**
 * ✏️ Update policy
 * @route PUT /api/policies/:id
 * @access Admin, SuperAdmin
 */
export const updatePolicy = asyncHandler(async (req, res) => {
  const { id } = req.params;
  const { role, action, conditions, effect, isActive } = req.body;

  const policy = await Policy.findById(id);
  if (!policy) {
    throw new ApiError(404, "Policy not found");
  }

  let roleExists;
  // Validate role if provided
  if (role && role !== policy.role.toString()) {
    roleExists = await Role.findOne({ name: role });

    if (!roleExists) {
      throw new ApiError(404, "Role not found");
    }
  }

  // Update fields
  if (role) policy.role = roleExists._id;
  if (action) policy.action = action;
  if (conditions !== undefined) policy.conditions = conditions;
  if (effect) policy.effect = effect;
  if (isActive !== undefined) policy.isActive = isActive;

  await policy.save();

  const updatedPolicy = await Policy.findById(id)
    .populate("role", "name description")
    .populate("createdBy", "username email");

  // Log audit event
  await logAuditEvent({
    userId: req.user._id,
    action: "update:policy",
    resource: id,
    status: "allowed",
    metadata: { changes: req.body },
  });

  res
    .status(200)
    .json(new ApiResponse(200, updatedPolicy, "Policy updated successfully"));
});

/**
 * 🗑️ Delete policy
 * @route DELETE /api/policies/:id
 * @access SuperAdmin only
 */
export const deletePolicy = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const policy = await Policy.findById(id);
  if (!policy) {
    throw new ApiError(404, "Policy not found");
  }

  await Policy.findByIdAndDelete(id);

  // Log audit event
  await logAuditEvent({
    userId: req.user._id,
    action: "delete:policy",
    resource: id,
    status: "allowed",
  });

  res
    .status(200)
    .json(
      new ApiResponse(200, { policyId: id }, "Policy deleted successfully")
    );
});

/**
 * 🔄 Toggle policy status (activate/deactivate)
 * @route PATCH /api/policies/:id/toggle
 * @access Admin, SuperAdmin
 */
export const togglePolicyStatus = asyncHandler(async (req, res) => {
  const { id } = req.params;

  const policy = await Policy.findById(id);
  if (!policy) {
    throw new ApiError(404, "Policy not found");
  }

  policy.isActive = !policy.isActive;
  await policy.save();

  // Log audit event
  await logAuditEvent({
    userId: req.user._id,
    action: "toggle:policy",
    resource: id,
    status: "allowed",
    metadata: { newStatus: policy.isActive },
  });

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { policyId: id, isActive: policy.isActive },
        `Policy ${policy.isActive ? "activated" : "deactivated"} successfully`
      )
    );
});

/**
 * 📊 Get policies by role
 * @route GET /api/policies/role/:roleId
 * @access Admin, SuperAdmin
 */
export const getPoliciesByRole = asyncHandler(async (req, res) => {
  const { roleId } = req.params;

  const role = await Role.findById(roleId);
  if (!role) {
    throw new ApiError(404, "Role not found");
  }

  const policies = await Policy.find({ role: roleId, isActive: true })
    .populate("role", "name description")
    .sort({ createdAt: -1 });

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { policies, count: policies.length, role: role.name },
        `Policies for role '${role.name}' retrieved successfully`
      )
    );
});

/**
 * 📊 Get policies by action
 * @route GET /api/policies/action/:action
 * @access Admin, SuperAdmin
 */
export const getPoliciesByAction = asyncHandler(async (req, res) => {
  const { action } = req.params;

  const policies = await Policy.find({ action, isActive: true })
    .populate("role", "name description")
    .sort({ createdAt: -1 });

  res
    .status(200)
    .json(
      new ApiResponse(
        200,
        { policies, count: policies.length },
        `Policies for action '${action}' retrieved successfully`
      )
    );
});

/**
 * 🧪 Test policy evaluation
 * @route POST /api/policies/test
 * @access Admin, SuperAdmin
 */
export const testPolicy = asyncHandler(async (req, res) => {
  const { policyId, testContext } = req.body;

  if (!policyId) {
    throw new ApiError(400, "Policy ID is required");
  }

  const policy = await Policy.findById(policyId).populate("role", "name");
  if (!policy) {
    throw new ApiError(404, "Policy not found");
  }

  // Build context from provided test data or current request
  const context = testContext || buildContext(req, req.user);

  // Evaluate the policy
  const result = evaluateComplexPolicy(
    {
      conditions: policy.conditions,
      effect: policy.effect,
      name: `${policy.role.map((r) => r.name).join(", ")} - ${policy.action}`,
    },
    context
  );

  // Log audit event
  await logAuditEvent({
    userId: req.user._id,
    action: "test:policy",
    resource: policyId,
    status: result.allowed ? "allowed" : "denied",
    metadata: { result, context },
  });

  res.status(200).json(
    new ApiResponse(
      200,
      {
        policy: {
          id: policy._id,
          action: policy.action,
          effect: policy.effect,
          conditions: policy.conditions,
        },
        evaluation: result,
        context,
      },
      "Policy evaluation completed"
    )
  );
});


/**
 * 🌱 Seeds default ABAC policies (attribute-based)
 */
export const seedDefaultPolicies = async () => {
  try {
    console.log("🔐 Starting ABAC Policy Seeding...");

    const existingPolicies = await Policy.countDocuments();
    if (existingPolicies > 0) {
      console.log("⚠️ Policies already exist, skipping creation.");
      return;
    }

    const defaultPolicies = [
      {
        name: "finance_report_access",
        description:
          "Allow Finance department to access confidential reports during office hours (9 AM–6 PM)",
        effect: "allow",
        targetResource: "report",
        conditions: [
          { attribute: "user.department", operator: "==", value: "Finance" },
          {
            attribute: "environment.time",
            operator: "inRange",
            value: ["09:00", "18:00"],
          },
          {
            attribute: "resource.sensitivity",
            operator: "==",
            value: "confidential",
          },
        ],
        isActive: true,
      },
      {
        name: "location_based_access",
        description:
          "Allow users to access dashboard only if logged in from India",
        effect: "allow",
        targetResource: "dashboard",
        conditions: [
          { attribute: "user.location", operator: "==", value: "India" },
        ],
        isActive: true,
      },
      {
        name: "night_access_restriction",
        description: "Deny access to project editor during non-working hours",
        effect: "deny",
        targetResource: "project",
        conditions: [
          {
            attribute: "environment.time",
            operator: "outRange",
            value: ["08:00", "20:00"],
          },
          { attribute: "user.role", operator: "==", value: "editor" },
        ],
        isActive: true,
      },
    ];

    await Policy.insertMany(defaultPolicies);
    console.log("✅ Default ABAC policies created successfully.");
  } catch (error) {
    console.error("❌ Error seeding ABAC policies:", error.message);
  }
};
