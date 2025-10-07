import mongoose from "mongoose";

const resourceSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    type: {
      type: String,
      required: true,
      enum: ["file", "project", "report", "dashboard", "api"],
    },

    sensitivity: {
      type: String,
      enum: ["public", "internal", "confidential", "restricted"],
      default: "internal",
    },

    department: {
      type: String,
      trim: true,
    },

    location: {
      type: String,
      trim: true,
    },

    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },

    description: {
      type: String,
      trim: true,
    },

    metadata: {
      type: Object,
      default: {},
    },

    isActive: {
      type: Boolean,
      default: true,
    },

    tags: {
      type: [String],
      default: [],
    },
  },
  {
    timestamps: true,
  }
);

export const Resource = mongoose.model("Resource", resourceSchema);
