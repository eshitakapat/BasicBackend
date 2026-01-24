import { Router } from "express";

import {
  registeredUser,
  login,
  logoutUser,
  getCurrentUser,
  refreshAccessToken,
  forgotPasswordRequest,
  resetForgotPassword,
  changeCurrentPassword,
  resendEmailVerification,
  verifyEmail
} from "../controllers/auth.controllers.js";

import { validate } from "../middlewares/validator.middleware.js";
import {
  userRegisterValidator,
  userLoginValidator,
  userResetForgotPasswordValidator,
  userChangeCurrentPasswordValidator
} from "../validators/index.js";

import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

/* ---------------- UNSECURED ROUTES ---------------- */

router.post(
  "/register",
  userRegisterValidator(),
  validate,
  registeredUser
);

router.post(
  "/login",
  userLoginValidator(),
  validate,
  login
);

router.get(
  "/verify-email/:verificationToken",
  verifyEmail
);

router.post(
  "/refresh-token",
  refreshAccessToken
);

router.post(
  "/forgot-password",
  forgotPasswordRequest
);

router.post(
  "/reset-password/:resetToken",
  userResetForgotPasswordValidator(),
  validate,
  resetForgotPassword
);

/* ---------------- SECURED ROUTES ---------------- */

router.post(
  "/logout",
  verifyJWT,
  logoutUser
);

router.post(
  "/current-user",
  verifyJWT,
  getCurrentUser
);

router.post(
  "/change-password",
  verifyJWT,
  userChangeCurrentPasswordValidator(),
  validate,
  changeCurrentPassword
);

router.post(
  "/resend-email-verification",
  verifyJWT,
  resendEmailVerification
);

export default router;
