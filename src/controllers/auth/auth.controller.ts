import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.model";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import crypto from 'crypto';
import { sendEmail } from "../../lib/email";
import { createAccessToken, createRefreshToken, verifyRefreshHandler } from "../../lib/token";

function getAppUrl() {
    return process.env.APP_URL || `http://localhost:${process.env.PORT || 3000}`;
}

export const registerHandler = async (req: Request, res: Response) => {
    try {
        const result = registerSchema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({
                message: "Invalid request data",
                errors: result.error.flatten(),
            });
        }
        const { email, password, name } = result.data;
        const normalizedEmail = email.toLowerCase().trim();
        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) {
            return res.status(409).json({ message: "Email already in use" });
        }
        const passwordHash = await hashPassword(password);
        const newUser = new User({
            email: normalizedEmail,
            password: passwordHash,
            name,
            role: "user",
            isEmailVerified: false,
            twoFactorEnabled: false,
        });
        await newUser.save();
        // email verification logic can be added here
        const verifyToken = jwt.sign(
            {
                sub: newUser._id,
            },
            process.env.JWT_ACCESS_SECRET!,
            { expiresIn: "1d" }
        );
        const verifyLink = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;
        await sendEmail(
            newUser.email,
            "Verify your email",
            `<p>Please verify your email by clicking the link below:</p>
                <p><a href="${verifyLink}">${verifyLink}</a></p>
                <p>This link will expire in 24 hours.</p>
            `
        );
        return res.status(201).json({
            message: "User registered successfully", user: {
                id: newUser._id,
                email: newUser.email,
                name: newUser.name,
                role: newUser.role,
                isEmailVerified: newUser.isEmailVerified,
            }
        });
    } catch (error) {
        console.error("Registration error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
};

export const verifyEmailHandler = async (req: Request, res: Response) => {
    const { token } = req.query;
    if (!token || Array.isArray(token)) {
        return res.status(400).json({ message: "Invalid or missing token" });
    }
    try {
        const payload = jwt.verify(token as string, process.env.JWT_ACCESS_SECRET!) as { sub: string };
        const user = await User.findById(payload.sub);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        if (user.isEmailVerified) {
            return res.status(400).json({ message: "Email is already verified" });
        }
        user.isEmailVerified = true;
        await user.save();
        return res.status(200).json({ message: "Email verified successfully" });
    } catch (error) {
        console.error("Email verification error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const loginHandler = async (req: Request, res: Response) => {
    try {
        const result = loginSchema.safeParse(req.body);
        if (!result.success) {
            return res.status(400).json({
                message: "Invalid request data",
                errors: result.error.flatten(),
            });
        }
        const { email, password } = result.data;
        const normalizedEmail = email.toLowerCase().trim();
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        const ok = await checkPassword(password, user.password);
        if (!ok) {
            return res.status(401).json({ message: "Invalid email or password" });
        }
        if (!user.isEmailVerified) {
            const accessToken = createAccessToken(user._id.toString(), user.role, user.tokenVersion, true);

            return res.status(200).json({
                message: "Email is not verified. Please verify your email to unlock full access.",
                accessToken,
                user: {
                    id: user._id,
                    email: user.email,
                    name: user.name,
                    role: user.role,
                    isEmailVerified: user.isEmailVerified,
                    twoFactorEnabled: user.twoFactorEnabled,
                }
            });
        }

        const accessToken = createAccessToken(user._id.toString(), user.role, user.tokenVersion);
        const refreshToken = createRefreshToken(user._id.toString(), user.tokenVersion);

        const isProd = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        });
        return res.status(200).json({
            message: "Login successful", accessToken, user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled,
            }
        });
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const refreshHandler = async (req: Request, res: Response) => {
    try {
        const token = req.cookies.refreshToken as string | undefined;
        if (!token) {
            return res.status(401).json({
                message: "Missing refresh token"
            });
        }
        const payload = verifyRefreshHandler(token);
        const user = await User.findById(payload.sub);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        if (user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({ message: "Refresh Token invalid" });
        }
        const newAccessToken = createAccessToken(user.id, user.role, user.tokenVersion);
        const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);
        const isProd = process.env.NODE_ENV === "production";
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: isProd ? "strict" : "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        })
        return res.status(200).json({
            message: "Login successful", newAccessToken, user: {
                id: user._id,
                email: user.email,
                name: user.name,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled,
            }
        });
    } catch (error) {
        console.error("Token refresh error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const logoutHandler = async (_req: Request, res: Response) => {
    res.clearCookie("refreshToken", {
        path: '/', httpOnly: true
    });
    res.status(200).json({ message: "logged out " })
}

export const forgetPassword = async (req: Request, res: Response) => {
    const { email } = req.body as { email?: string };
    if (!email) {
        return res.status(400).json({ message: "Email is required" });
    }
    const normalizedEmail = email.toLowerCase().trim();
    try {
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.json({ message: "if this user account exist , we will send you a reset link" });
        }
        const rawTOken = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(rawTOken).digest('hex');
        user.resetPasswordToken = tokenHash;
        user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);
        await user.save();
        const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawTOken}`

        await sendEmail(
            user.email,
            "Reset your password",
            `
                <p>Hello,</p>

                <p>You requested to reset your password.</p>

                <p>
                    <a href="${resetUrl}">${resetUrl}</a>
                </p>

                <p>If you did not request this, please ignore this email.</p>
                `
        );

        return res.json({ message: "if this user account exist , we will send you a reset link" });

    } catch (error) {
        console.error("Token refresh error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}

export const resetPasswordHandler = async (req: Request, res: Response) => {
    const { token, password } = req.body as { token?: string; password?: string };
    if (!token) {
        return res.status(400).json({ message: "Reset token is missing " });
    }
    if (!password || password.length < 6)
        return res.status(400).json({ message: "password atLeast be 6 char long  " });
    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const user = await User.findOne({ resetPasswordToken: tokenHash, resetPasswordExpires: { $gt: new Date() } });
        if (!user) {
            return res.status(400).json({ message: "Invalid or expired Token" });
        }
        const newPasswordHash = await hashPassword(password);
        user.password = newPasswordHash;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        user.tokenVersion = user.tokenVersion + 1;
        await user.save();
        return res.json({ message: "password reset successfully" })

    } catch (error) {
        console.error("Token refresh error:", error);
        return res.status(500).json({ message: "Internal server error" });
    }
}