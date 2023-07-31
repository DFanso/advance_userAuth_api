// controllers/userController.js
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/user");
const { validationResult } = require("express-validator");
const { check } = require("express-validator");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const mailConfig = require("../config/mail");


exports.validate = (method) => {
    switch (method) {
      case "register":
      case "login": {
        return [
          check("username", "Username is required").notEmpty(),
          check("password", "Password is required").notEmpty(),
        ];
      }
      default: {
        return [];
      }
    }
  };
  
  exports.register = async (req, res) => {
    const { username, password } = req.body;
  
    // Check if the username already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already exists" });
    }
  
    // Hash the password before storing it
    const hashedPassword = await bcrypt.hash(password, 10);
  
    // Create a verification token
    const token = crypto.randomBytes(20).toString("hex");
  
    // Create a new user in the database
    const user = new User({
      username,
      password: hashedPassword,
      verificationToken: token,
    });
  
    try {
      await user.save();
  
      // Send a verification email to the user
      const transporter = nodemailer.createTransport(mailConfig);
  
      const mailOptions = {
        to: user.username,
        from: "noreply@example.com",
        subject: "Email Verification",
        text: `Please click on the following link, or paste it into your browser to verify your email address:
  http://${req.headers.host}/api/users/verify/${token}
  If you did not request this, please ignore this email.`,
      };
  
      transporter.sendMail(mailOptions, (err) => {
        if (err) {
          console.log(err);
        }
      });
  
      res.status(201).json({ message: "User created successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error registering user", error: err });
    }
  };
  
  exports.verifyEmail = async (req, res) => {
    const { token } = req.params;
  
    const user = await User.findOne({ verificationToken: token });
  
    if (!user) {
      return res.status(400).json({ message: "Invalid token" });
    }
  
    user.verificationToken = undefined;
    await user.save();
  
    res.status(200).json({ message: "Email verified" });
  };

exports.login = async (req, res) => {
  const { username, password } = req.body;

  const user = await User.findOne({ username });

  if (!user || !(await user.comparePassword(password))) {
    return res.status(400).json({ message: "Invalid username or password" });
  }

  const payload = {
    id: user.id,
    username: user.username,
  };

  const token = jwt.sign(payload, process.env.SECRET_KEY, { expiresIn: "1h" });

  res.status(200).json({ message: "Logged in successfully", token });
};

exports.profile = (req, res) => {
  res.status(200).json({ message: "Welcome to your profile", user: req.user });
};

exports.requireRole = (role) => {
    return (req, res, next) => {
      if (req.user && req.user.role === role) {
        next();
      } else {
        res.status(403).json({ message: "Forbidden" });
      }
    };
  };

  exports.forgotPassword = async (req, res) => {
    const { username } = req.body;
    const user = await User.findOne({ username });
  
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
  
    const token = crypto.randomBytes(20).toString("hex");
    user.passwordResetToken = token;
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour
    await user.save();
  
    const transporter = nodemailer.createTransport(mailConfig);
  
    const mailOptions = {
      to: user.username,
      from: "noreply@example.com",
      subject: "Password Reset",
      text: `You are receiving this because you (or someone else) have requested the reset of the password for your account.
  Please click on the following link, or paste it into your browser to complete the process:
  http://${req.headers.host}/api/users/reset-password/${token}
  If you did not request this, please ignore this email and your password will remain unchanged.`,
    };
  
    transporter.sendMail(mailOptions, (err) => {
      if (err) {
        return res.status(500).json({ message: "Error sending email" });
      }
      res.status(200).json({ message: "Password reset email sent" });
    });
  };
  
  exports.resetPassword = async (req, res) => {
    const { token } = req.params;
    const { newPassword } = req.body;
  
    const user = await User.findOne({
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() },
    });
  
    if (!user) {
      return res.status(400).json({ message: "Password reset token is invalid or has expired" });
    }
  
    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();
  
    res.status(200).json({ message: "Password reset successful" });
  };

