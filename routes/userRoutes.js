// routes/userRoutes.js
const express = require("express");
const passport = require("passport");
const userController = require("../controllers/userController");
const { check } = require("express-validator");

const router = express.Router();

const { 
  register,
  login,
  getProfile,
  getAdminArea,
  forgotPassword,
  resetPassword,
  validate,
} = require("../controllers/userController");


router.post(
  "/register",
  userController.validate("register"),
  userController.register
);
router.post(
  "/login",
  userController.validate("login"),
  userController.login
);
router.get(
  "/profile",
  passport.authenticate("jwt", { session: false }),
  userController.profile
);
router.get(
  "/admin",
  passport.authenticate("jwt", { session: false }),
  userController.requireRole("admin"),
  (req, res) => {
    res.status(200).json({ message: "Welcome to the admin area" });
  }
);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

module.exports = router;
