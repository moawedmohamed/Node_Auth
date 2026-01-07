import express, { Response, Request } from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRouter from './routes/auth.route';
import morgan from 'morgan';
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"));
app.get('/health', (_req: Request, res: Response) => {

    res.status(200).json({ status: 'OK', message: 'Server is healthy' });
});
app.use('/auth', authRouter);
export default app;
// Connect to Database