import { Router } from "express";
import {
    forgetPassword, googleAuthCallbackHandler, googleAuthStartHandler,
    loginHandler, logoutHandler, refreshHandler,
    registerHandler, resetPasswordHandler, twoFactorSetupHandler, twoFactorVerifyHandler, verifyEmailHandler
} from "../controllers/auth/auth.controller";
import requireAuth from "../middleware/requireAuth";


const router = Router();

router.post("/register", registerHandler);
router.post('/login', loginHandler);
router.get('/verify-email', verifyEmailHandler);
router.post('/refresh', refreshHandler);
router.post('/logout', logoutHandler);
router.post('/forget-password', forgetPassword);
router.post('/reset-password', resetPasswordHandler);
router.get('/google', googleAuthStartHandler);
router.get('/google/callback', googleAuthCallbackHandler);
router.post('/2fa/setup', requireAuth, twoFactorSetupHandler);
router.post('/2fa/verify', requireAuth, twoFactorVerifyHandler);

export default router;