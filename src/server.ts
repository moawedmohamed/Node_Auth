import dotenv from 'dotenv';
dotenv.config();
import { connectDB } from "./config/db";
import http from 'http';
import app from './app';
const startServer = async () => {
    await connectDB();
    const server = http.createServer(app);
    server.listen(process.env.PORT || 5000, () => {
        console.log(`Server is running on port ${process.env.PORT || 5000}`);
    });
};
startServer().catch((error) => {
    console.error("Failed to start server:", error);
    process.exit(1);
});
