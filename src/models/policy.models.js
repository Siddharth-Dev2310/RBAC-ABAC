import mongoose from "mongoose";

const policySchema = new mongoose.Schema(
  {
    role: [
      {
        type: mongoose.Schema.Types.ObjectId,
        ref: "Role",
        required: true,
      },
    ],

    action: {
      type: String, // e.g. "read:user", "edit:project"
      required: true,
    },

    conditions: {
      type: Object, // Dynamic attributes like { ownResource: true, department: "IT" }
      default: {},
    },

    effect: {
      type: String,
      enum: ["allow", "deny"],
      default: "allow",
    },

    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },

    isActive: {
      type: Boolean,
      default: true,
    },
  },
  { timestamps: true }
);

export const Policy = mongoose.model("Policy", policySchema);
