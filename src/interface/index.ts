import { Request } from "express";

export interface userInfo {
    id: string;
    name?: string | null;
    email: string;
    role: string;
    isEmailVerified: boolean
    twoFactorSecret: string | null,
    createdAt?: Date
}
export interface AuthRequest extends Request {
    user?: userInfo;
}