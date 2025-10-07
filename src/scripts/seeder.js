import dotenv from "dotenv";
import { connectDB } from "../db/index.js";
import { seedDefaultData } from "../controller/seeder.controller.js";

dotenv.config();

const startSeeding = async () => {
  await connectDB();
  await seedDefaultData();
  process.exit(0); 
}

startSeeding()
    .catch((error) => {
        console.error("Seeding failed", error);
        process.exit(1);
    });

