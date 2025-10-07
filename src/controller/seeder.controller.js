import { Role } from "../models/role.models.js";
import { Policy } from "../models/policy.models.js";
import { User } from "../models/users.models.js";

/**
 * 🌱 Seed default roles, policies, and users (RBAC + ABAC base)
 * This function properly hashes passwords and ensures data integrity
 */
export const seedDefaultData = async (req, res) => {
  try {
    console.log("🚀 Starting RBAC + ABAC seeding process...");
    console.log("═".repeat(60));

    // === 1️⃣ Seed Roles ===
    console.log("\n📋 Step 1: Seeding Roles...");
    const existingRoles = await Role.find({});

    let superAdminRole, adminRole, editorRole, viewerRole;

    if (existingRoles.length > 0) {
      console.log("✅ Roles already exist, fetching existing roles.");
      superAdminRole = await Role.findOne({ name: "superadmin" });
      adminRole = await Role.findOne({ name: "admin" });
      editorRole = await Role.findOne({ name: "editor" });
      viewerRole = await Role.findOne({ name: "viewer" });

      console.log(`   Found ${existingRoles.length} existing roles`);
    } else {
      const rolesData = [
        {
          name: "superadmin",
          description: "Full system access (cannot be deleted)",
          isSystemRole: true,
          permissions: [
            { action: "create", resource: "user" },
            { action: "delete", resource: "user" },
            { action: "read", resource: "user" },
            { action: "update", resource: "user" },
            { action: "manage", resource: "roles" },
            { action: "manage", resource: "policies" },
            { action: "manage", resource: "resources" },
          ],
        },
        {
          name: "admin",
          description: "Manage organization users and resources",
          permissions: [
            { action: "create", resource: "user" },
            { action: "read", resource: "user" },
            { action: "update", resource: "user" },
            { action: "read", resource: "report" },
            { action: "create", resource: "resource" },
            { action: "update", resource: "resource" },
          ],
        },
        {
          name: "editor",
          description: "Create and edit project resources",
          permissions: [
            { action: "create", resource: "project" },
            { action: "update", resource: "project" },
            { action: "read", resource: "project" },
            { action: "create", resource: "resource" },
            { action: "update", resource: "resource" },
          ],
        },
        {
          name: "viewer",
          description: "View only permissions",
          permissions: [
            { action: "read", resource: "project" },
            { action: "read", resource: "report" },
            { action: "read", resource: "resource" },
          ],
        },
      ];

      const createdRoles = await Role.insertMany(rolesData);
      superAdminRole = createdRoles.find((r) => r.name === "superadmin");
      adminRole = createdRoles.find((r) => r.name === "admin");
      editorRole = createdRoles.find((r) => r.name === "editor");
      viewerRole = createdRoles.find((r) => r.name === "viewer");

      console.log(`✅ Created ${createdRoles.length} roles successfully:`);
      createdRoles.forEach((role) =>
        console.log(`   - ${role.name}: ${role.description}`)
      );
    }

    // === 2️⃣ Seed Policies ===
    console.log("\n🔐 Step 2: Seeding ABAC Policies...");
    const existingPolicies = await Policy.find({});

    if (existingPolicies.length > 0) {
      console.log(
        `✅ Policies already exist (${existingPolicies.length} found), skipping policy creation.`
      );
    } else {
      const policiesData = [
        // Superadmin policies - Full access to everything
        {
          role: [superAdminRole._id],
          action: "manage:all",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [superAdminRole._id],
          action: "delete:user",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [superAdminRole._id],
          action: "delete:policy",
          conditions: {},
          effect: "allow",
          isActive: true,
        },

        // Admin policies - Manage users and resources
        {
          role: [adminRole._id],
          action: "create:user",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [adminRole._id],
          action: "edit:user",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [adminRole._id],
          action: "read:user",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [adminRole._id],
          action: "create:resource",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [adminRole._id],
          action: "edit:resource",
          conditions: {},
          effect: "allow",
          isActive: true,
        },

        // Editor policies - Create and edit projects (department-restricted)
        {
          role: [editorRole._id],
          action: "create:project",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [editorRole._id],
          action: "edit:project",
          conditions: { department: "sales" },
          effect: "allow",
          isActive: true,
        },
        {
          role: [editorRole._id],
          action: "read:project",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [editorRole._id],
          action: "create:resource",
          conditions: {},
          effect: "allow",
          isActive: true,
        },

        // Viewer policies - Read-only access (own resources only)
        {
          role: [viewerRole._id],
          action: "read:user",
          conditions: { ownResource: true },
          effect: "allow",
          isActive: true,
        },
        {
          role: [viewerRole._id],
          action: "read:project",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [viewerRole._id],
          action: "read:resource",
          conditions: {},
          effect: "allow",
          isActive: true,
        },

        // Multi-role policies - Both admin and superadmin can manage policies
        {
          role: [adminRole._id, superAdminRole._id],
          action: "create:policy",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
        {
          role: [adminRole._id, superAdminRole._id],
          action: "edit:policy",
          conditions: {},
          effect: "allow",
          isActive: true,
        },
      ];

      const createdPolicies = await Policy.insertMany(policiesData);
      console.log(
        `✅ Created ${createdPolicies.length} ABAC policies successfully:`
      );

      // Group by role for better readability
      const policiesByRole = createdPolicies.reduce((acc, policy) => {
        // Handle role array - get role names for each role in the policy
        policy.role.forEach((roleId) => {
          const roleName =
            roleId.toString() === superAdminRole._id.toString()
              ? "superadmin"
              : roleId.toString() === adminRole._id.toString()
              ? "admin"
              : roleId.toString() === editorRole._id.toString()
              ? "editor"
              : "viewer";

          if (!acc[roleName]) acc[roleName] = [];
          acc[roleName].push(policy.action);
        });
        return acc;
      }, {});

      Object.entries(policiesByRole).forEach(([role, actions]) => {
        console.log(`   ${role}: ${actions.join(", ")}`);
      });
    }

    // === 3️⃣ Seed Users (with properly hashed passwords) ===
    console.log("\n👥 Step 3: Seeding Users...");
    const existingUsers = await User.find({});

    if (existingUsers.length > 0) {
      console.log(
        `✅ Users already exist (${existingUsers.length} found), skipping user creation.`
      );
      console.log("   Existing users:");
      existingUsers.forEach((user) =>
        console.log(`   - ${user.username} (${user.email})`)
      );
    } else {
      console.log(
        "🔐 Preparing user data (passwords will be hashed by pre-save hook)..."
      );

      // Create users with plain passwords - the pre-save hook will hash them
      const usersData = [
        {
          username: "superadmin",
          email: "superadmin@securecloud.com",
          password: "SuperAdmin@123", // Plain password - will be hashed by pre-save hook
          role: superAdminRole._id,
          department: "IT",
          location: "Global",
          refreshToken: `refresh-${Date.now()}-superadmin`,
          isActive: true,
        },
        {
          username: "adminuser",
          email: "admin@securecloud.com",
          password: "Admin@123", // Plain password - will be hashed by pre-save hook
          role: adminRole._id,
          department: "HR",
          location: "India",
          refreshToken: `refresh-${Date.now()}-admin`,
          isActive: true,
        },
        {
          username: "editoruser",
          email: "editor@securecloud.com",
          password: "Editor@123", // Plain password - will be hashed by pre-save hook
          role: editorRole._id,
          department: "sales",
          location: "USA",
          refreshToken: `refresh-${Date.now()}-editor`,
          isActive: true,
        },
        {
          username: "vieweruser",
          email: "viewer@securecloud.com",
          password: "Viewer@123", // Plain password - will be hashed by pre-save hook
          role: viewerRole._id,
          department: "Finance",
          location: "India",
          refreshToken: `refresh-${Date.now()}-viewer`,
          isActive: true,
        },
      ];

      // Create users - pre-save hook will automatically hash passwords
      const createdUsers = await User.create(usersData);

      console.log("✅ Passwords hashed securely by pre-save hook");

      console.log(`✅ Created ${createdUsers.length} users successfully:`);
      createdUsers.forEach((user) => {
        console.log(`   - ${user.username} (${user.email})`);
        console.log(
          `     Role: ${user.role}, Department: ${user.department || "N/A"}`
        );
      });
    }

    // === 4️⃣ Summary ===
    console.log("\n" + "═".repeat(60));
    console.log("🌱 Seeding Complete!");
    console.log("═".repeat(60));

    const totalRoles = await Role.countDocuments();
    const totalPolicies = await Policy.countDocuments();
    const totalUsers = await User.countDocuments();

    console.log("\n📊 Database Summary:");
    console.log(`   Roles: ${totalRoles}`);
    console.log(`   Policies: ${totalPolicies}`);
    console.log(`   Users: ${totalUsers}`);

    console.log("\n🔑 Test Credentials:");
    console.log("   SuperAdmin: superadmin@securecloud.com / SuperAdmin@123");
    console.log("   Admin:      admin@securecloud.com / Admin@123");
    console.log("   Editor:     editor@securecloud.com / Editor@123");
    console.log("   Viewer:     viewer@securecloud.com / Viewer@123");

    console.log("\n✅ You can now test login with these credentials!\n");
  } catch (error) {
    console.error("\n❌ Error during seeding:");
    console.error("   Message:", error.message);
    console.error("   Stack:", error.stack);
    throw error;
  }
};
