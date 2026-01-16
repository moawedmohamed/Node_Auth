import { Request, Response, Router } from "express";
import requireAuth from "../middleware/requireAuth";
import { requireRole } from "../middleware/requireRole";
import { User } from "../models/user.model";
import { userInfo } from "../interface";

const router = Router();

router.get('/users', requireAuth, requireRole('admin'), async (_req: Request, res: Response) => {
    try {
        const users: userInfo[] = await User.find(
            {},
            {
                email: 1,
                name: 1,
                role: 1,
                isEmailVerified: 1,
                createdAt: 1
            }
        ).sort({ createdAt: -1 });
        //  ** another way to fetch users
        // const users = await User.find().select("email name isEmailVerified createdAt").sort({ createdAt: -1 })
        const result = users.map((u: userInfo) => ({
            id: u.id.toString(),
            name: u.name,
            email: u.email,
            isEmailVerified: u.isEmailVerified,
            createdAt: u.createdAt
        }))
        return res.json({ users: result })
    } catch (error) {
        console.error("admin function error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
})

export default router;