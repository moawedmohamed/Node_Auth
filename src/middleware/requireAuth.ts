import { NextFunction, Request, Response } from "express";
import { verifyAccessToken } from "../lib/token";
import { User } from "../models/user.model";
import { AuthRequest } from "../interface";

const requireAuth = async (req: AuthRequest, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer "))
        return res.status(401).json({ message: "you are not auth user " })
    const token = authHeader?.split(" ")[1];
    try {
        const payload = verifyAccessToken(token);
        const user = await User.findById(payload.sub);
        if (!user)
            return res.status(401).json({ message: "user not found " })
        if (user.tokenVersion !== payload.tokenVersion)
            return res.status(401).json({ message: "token invalid " })

        req.user = {
            id: user.id,
            name: user.name,
            email: user.email,
            role: user.role,
            isEmailVerified: user.isEmailVerified,
            twoFactorSecret: user.twoFactorSecret ?? null
        }
        next();
    } catch (error) {
        console.error("middleware error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export default requireAuth;