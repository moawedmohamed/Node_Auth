import { Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";
import { AuthRequest } from "../interface";

const userRouter = Router();
userRouter.get('/me', requireAuth, (req: AuthRequest, res: Response) => {
    return res.json({ user: req.user })
})

export default userRouter;