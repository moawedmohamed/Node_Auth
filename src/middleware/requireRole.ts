import { NextFunction, Response } from "express"
import { AuthRequest } from "../interface"

export const requireRole = (role: 'user' | 'admin') => {
    return (req: AuthRequest, res: Response, next: NextFunction) => {
        if (!req.user) {
            return res.status(401).json({ message: "user not Auth" });

        }
        if (req.user.role !== 'admin') {
            return res.status(401).json({ message: "you don't have correct role access " });

        }
        next()
    }

}