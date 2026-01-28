import { Router } from "express";

import {
    addMembersToProject , createProject , deleteMember , getProjects , getProjectsById, getProjectMembers , updateMemberRole , deleteProject , updateProject
} from "../controllers/project.controllers.js";

import { validate } from "../middlewares/validator.middleware.js";
import {
addMemberToProjectValidator , createProjectValidator
} from "../validators/index.js";

import { verifyJWT , validateProjectPermission } from "../middlewares/auth.middleware.js";
import { AvailableUserRole, UserRolesEnum } from "../utils/constants.js";

const router = Router();
router.use(verifyJWT)


router
.route("/")
.get(getProjects)
.post(createProjectValidator() , validate , createProject)

router
.route("/:projectId")
.get(validateProjectPermission(AvailableUserRole) , getProjectsById)
.put(
    validateProjectPermission([UserRolesEnum.ADMIN]) ,
    createProjectValidator(),
    validate,
    updateProject)

    .delete(
        validateProjectPermission([UserRolesEnum.ADMIN]),

        deleteProject
    )

    router
    .route("/:projectId/members")
    .get(getProjectMembers)
    .post(
        validateProjectPermission([UserRolesEnum.ADMIN]),
        addMemberToProjectValidator(),
        validate ,
        addMembersToProject
    )

    router
    .route("/:projectId/members/:userId")
    .put(validateProjectPermission([UserRolesEnum.ADMIN]), 
     updateMemberRole)
    .delete(getProjectMembers)


export default router