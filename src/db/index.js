import { DB_NAME } from "../constants.js";
import mongoose from "mongoose";

export const connectDB = async () => {
  
  try {
    const connectionInstance = await mongoose.connect(
      `${process.env.MONGODB_URI}/${DB_NAME}`,
    );

    console.log(`\nMongoDB connected: ${connectionInstance.connection.host}`);
    console.log(`Using Database: ${DB_NAME}\n`);
  } catch (error) {
    console.error("Error connecting to the database", error);
    process.exit(1);
  }
};
