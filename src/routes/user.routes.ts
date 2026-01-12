import { Request, Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";
interface userInfo {
    id: string;
    name: string;
    email: string;
    role: string;
    isEmailVerified: boolean
}
export interface AuthRequest extends Request {
    user?: userInfo;
}
const userRouter = Router();
userRouter.get('/me', requireAuth, (req: AuthRequest, res: Response) => {
    return res.json({ user: req.user })
})

export default userRouter;