import dotenv from "dotenv";
import { connectDB } from "../db/index.js";
import { seedDefaultData } from "../controller/seeder.controller.js";
import { seedDefaultPolicies } from "../controller/policy.controller.js";

dotenv.config();

const startSeeding = async () => {
  try {
    await connectDB();
    await seedDefaultData();
    await seedDefaultPolicies(); 
    console.log("🎉 All Seeding Complete (RBAC + ABAC)!");
    process.exit(0);
  } catch (error) {
    console.error("❌ Error running full seeder:", error.message);
    process.exit(1);
  }
};

startSeeding();
