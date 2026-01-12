import { Router } from "express";
import { forgetPassword, googleAuthStartHandler, loginHandler, logoutHandler, refreshHandler, registerHandler, resetPasswordHandler, verifyEmailHandler } from "../controllers/auth/auth.controller";


const router = Router();

router.post("/register", registerHandler);
router.post('/login', loginHandler);
router.get('/verify-email', verifyEmailHandler);
router.post('/refresh', refreshHandler);
router.post('/logout', logoutHandler);
router.post('/forget-password', forgetPassword);
router.post('/reset-password', resetPasswordHandler);
router.get('/google', googleAuthStartHandler);
export default router;