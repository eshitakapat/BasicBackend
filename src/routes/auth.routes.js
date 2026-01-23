import {Router} from "express"
import { registeredUser } from "../controllers/auth.controllers.js"
import { login } from "../controllers/auth.controllers.js"
import { logoutUser} from "../controllers/auth.controllers.js"

import { validate } from "../middlewares/validator.middleware.js"
import {userRegisterValidator , userLoginValidator} from "../validators/index.js"

import {verifyJWT} from "../middlewares/auth.middleware.js"

const router = Router()
router.route("/register").post(userRegisterValidator() , validate , registeredUser)

router.route("/login").post
(userLoginValidator(), validate, login)

router.route("/login").post
(userLoginValidator(), validate, login)

router.route("/logout").post
(verifyJWT , logoutUser)

export default router