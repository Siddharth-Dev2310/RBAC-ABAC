import mongoose from "mongoose";

const permissionSchema = new mongoose.Schema({ 
    action: {
        type: String,
        required: true,
    },

    resource: {
        type: String,
        required: true,
    }
}, { _id: false });


const roleSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            unique: true,
            trim: true,
        },

        description: {
            type: String,
            required: true,
            trim: true,
        },

        permissions: {
            type: [permissionSchema],
            default: [],
        },

        isSystemRole: {
            type: Boolean,
            default: false,
        }

    },
    {
        timestamps: true,
    }
);

export const Role = mongoose.model("Role", roleSchema);