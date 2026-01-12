import express, { Response, Request } from 'express';
import cookieParser from 'cookie-parser';
import dotenv from 'dotenv';
import authRouter from './routes/auth.route';
import morgan from 'morgan';
import userRouter from './routes/user.routes';
dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(morgan("dev"));
app.get('/health', (_req: Request, res: Response) => {

    res.status(200).json({ status: 'OK', message: 'Server is healthy' });
});
app.use('/auth', authRouter);
app.use('/user', userRouter);
export default app;
// Connect to Database