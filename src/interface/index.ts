import { Request } from "express";

export interface userInfo {
    id: string;
    name?: string|null;
    email: string;
    role: string;
    isEmailVerified: boolean
    createdAt?: Date
}
export interface AuthRequest extends Request {
    user?: userInfo;
}