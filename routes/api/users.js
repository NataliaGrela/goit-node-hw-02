const express = require("express");
const passport = require("passport");
const jimp = require("jimp");
const fs = require("fs/promises");
const {
  register,
  getUserByEmail,
  login,
  logout,
  verifyToken,
  verifyAgain,
} = require("../../models/users/users");

const { upload, updateAvatar } = require("../../models/users/upload");

const router = express.Router();

const auth = (req, res, next) => {
  passport.authenticate("jwt", { session: false }, (err, user) => {
    if (!user || err || (user && !user.verify)) {
      return res.status(401).json({
        status: "error",
        code: 401,
        message: "Unauthorized",
        data: "Unauthorized",
      });
    }
    req.user = user;
    next();
  })(req, res, next);
};

router.get("/", async (req, res, next) => {
  res.json({});
});

router.post("/login", async (req, res, next) => {
  const data = {
    email: req.body.email,
    password: req.body.password,
  };
  const user = await login(data);
  if (!user) {
    res.status(400).json({
      status: "error",
      code: 400,
      message: "Incorrect login, password or user not verified",
      data: "Bad request",
    });
  } else {
    res.json({
      status: "success",
      code: 200,
      user,
    });
  }
});

router.post("/signup", async (req, res, next) => {
  const user = await getUserByEmail(req.body.email);
  const newUser = {
    email: req.body.email,
    password: req.body.password,
  };
  if (user) {
    return res.status(409).json({
      status: "error",
      code: 409,
      message: "Email is already in use",
      data: "Conflict",
    });
  } else {
    const registered = await register(newUser);
    if (registered) {
      res.status(201).json({
        status: "success",
        code: 201,
        data: {
          message: "Registration successful",
        },
      });
    }
  }
});

router.get("/current", auth, (req, res, next) => {
  const { email } = req.user;
  res.json({
    status: "success",
    code: 200,
    data: { ...req.user._doc },
  });
});

router.post("/logout", auth, async (req, res, next) => {
  const user = await logout(req.user._doc._id);
  if (user) {
    res.json({
      status: "success",
      code: 200,
      data: {
        message: `You have been logged out`,
      },
    });
  }
});

router.patch(
  "/avatars",
  auth,
  upload.single("picture"),
  async (req, res, next) => {
    const { path: tempUpload, originalname } = req.file;
    const { _id } = req.user;
    const user = await updateAvatar(_id, tempUpload, originalname);
    if (user) {
      res.json({
        status: "success",
        code: 200,
        data: {
          avatarURL: user.avatarURL,
        },
      });
    } else {
      res.status(400).json({
        status: "error",
        code: 400,
        message: "Error",
      });
    }
  }
);

router.get("/auth/verify/:verificationToken", async (req, res, next) => {
  const { verificationToken } = req.params;
  const user = await verifyToken(verificationToken);
  if (user) {
    res.json({
      status: "success",
      code: 200,
      message: "Verification successful",
    });
  } else {
    res.status(404).json({
      status: "error",
      code: 404,
      message: "User not found",
    });
  }
});

router.post("/verify/", async (req, res, next) => {
  const { email } = req.body;
  if (!email) {
    res.status(400).json({
      status: "error",
      code: 400,
      message: "Missing required field email",
    });
  }
  const user = await verifyAgain(email);
  if (user) {
    res.json({
      status: "success",
      code: 200,
      message: "Verification email sent",
    });
  } else {
    res.status(400).json({
      status: "error",
      code: 400,
      message: "Verification has already been passed",
    });
  }
});

module.exports = { router, auth };
