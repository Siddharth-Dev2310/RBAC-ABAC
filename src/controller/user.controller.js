import { asyncHandler } from "../utils/asyncHandler.utils.js";
import { User } from "../models/users.models.js";
import { ApiResponse } from "../utils/ApiResponse.utils.js";
import { Role } from "../models/role.models.js";
import { ApiError } from "../utils/ApiError.utils.js";
import { logAuditEvent } from "../utils/auditLogger.utils.js";

const createUser = asyncHandler(async (req, res) => {
  const {
    username,
    email,
    password,
    role: roleInput,
    department,
    location,
  } = req.body;

  // Check if user already exists
  const existingUser = await User.findOne({ $or: [{ username }, { email }] });
  if (existingUser) {
    return res
      .status(400)
      .json(new ApiResponse(400, null, "User already exists"));
  }

  // Resolve role: allow passing either role ObjectId or role name
  let resolvedRoleId = roleInput;
  if (!resolvedRoleId) {
    throw new ApiError(400, "Role is required");
  }
  // If it's not a 24-hex string treat as name
  const objectIdRegex = /^[a-fA-F0-9]{24}$/;
  if (!objectIdRegex.test(resolvedRoleId)) {
    const roleDoc = await Role.findOne({
      name: roleInput.toLowerCase().trim(),
    });
    if (!roleDoc) {
      throw new ApiError(400, `Role not found: ${roleInput}`);
    }
    resolvedRoleId = roleDoc._id;
  }

  // Create user (refreshToken left null until login)
  let user;
  try {
    user = await User.create({
      username,
      email,
      password,
      role: resolvedRoleId,
      department,
      location,
    });
  } catch (err) {
    if (err.name === "ValidationError") {
      throw new ApiError(400, "User validation failed", err.message);
    }
    throw err;
  }

  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken -__v"
  );

  if (!createdUser) {
    throw new ApiError(500, "Failed to retrieve created user");
  }

  // Log audit event
  await logAuditEvent(req.user._id, "create", "user", user._id, "success");

  // Send response
  return res
    .status(201)
    .json(new ApiResponse(201, { 
      user: {
        id: createdUser._id,
        email: createdUser.email,
        username: createdUser.username,
        role: createdUser.role,
        department: createdUser.department,
        location: createdUser.location
      }
    }, "User created successfully"));
});

const getUserById = asyncHandler(async (req, res) => {
  const user = await User.findById(req.params.id).populate(
    "role",
    "name permissions"
  );
  if (!user) {
    return res
      .status(404)
      .json(new ApiResponse(404, null, "User not found"));
  }
  return res
    .status(200)
    .json(new ApiResponse(200, {
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        role: user.role,
        department: user.department,
        location: user.location,
        isActive: user.isActive
      }
    }, "User retrieved successfully"));
});

const getAllUsers = asyncHandler(async (req, res) => {
  const users = await User.find().populate("role", "name permissions");

  if (users.length === 0) {
    return res
      .status(404)
      .json(new ApiResponse(404, null, "No users found"));
  }

  const formattedUsers = users.map(user => ({
    id: user._id,
    email: user.email,
    username: user.username,
    role: user.role,
    department: user.department,
    location: user.location,
    isActive: user.isActive
  }));

  return res
    .status(200)
    .json(new ApiResponse(200, { users: formattedUsers }, "Users retrieved successfully"));
});

const updateUser = asyncHandler(async (req, res) => {
  const {
    username,
    email,
    role: roleName,
    department,
    location,
    isActive,
  } = req.body;
  const user = await User.findById(req.params.id);
  if (!user) {
    return res
      .status(404)
      .json(new ApiResponse(404, null, "User not found"));
  }

  const roleDoc = roleName
    ? await Role.findOne({
        name: roleName.toLowerCase().trim(),
      })
    : null;

  // Update user fields
  user.username = username || user.username;
  user.email = email || user.email;
  user.role = roleDoc ? roleDoc._id : user.role;
  user.department = department || user.department;
  user.location = location || user.location;
  user.isActive = isActive !== undefined ? isActive : user.isActive;

  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, {
      user: {
        id: user._id,
        email: user.email,
        username: user.username,
        role: user.role,
        department: user.department,
        location: user.location,
        isActive: user.isActive
      }
    }, "User updated successfully"));
});

export { createUser, getUserById, getAllUsers, updateUser };
