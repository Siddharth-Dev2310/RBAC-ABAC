import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    action: {
      type: String,
      required: true,
      index: true,
    },

    resource: {
      type: String,
      required: true,
    },

    resourceType: {
      type: String,
    },

    status: {
      type: String,
      enum: ["allowed", "denied"],
      required: true,
      index: true,
    },

    reason: {
      type: String,
    },

    metadata: {
      type: Object,
      default: {},
    },

    ipAddress: {
      type: String,
    },

    userAgent: {
      type: String,
    },

    timestamp: {
      type: Date,
      default: Date.now,
      index: true,
    },
  },
  {
    timestamps: true,
  }
);

// Index for efficient querying
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, status: 1 });
auditLogSchema.index({ resource: 1, timestamp: -1 });

export const AuditLog = mongoose.model("AuditLog", auditLogSchema);
