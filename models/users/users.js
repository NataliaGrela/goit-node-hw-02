const express = require("express");
const jwt = require("jsonwebtoken");
const User = require("./model");
const bcrypt = require("bcryptjs");
const gravatar = require("gravatar");
const { nanoid } = require("nanoid");
const transporter = require("../../nodemailer");

const getUserByEmail = async email => {
  return User.findOne({ email });
};

function hashPassword(plaintextPassword) {
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(plaintextPassword, salt);
  return hash;
}

function comparePassword(plaintextPassword, hash) {
  const result = bcrypt.compareSync(plaintextPassword, hash);
  return result;
}

const register = async ({ email, password }) => {
  try {
    const hashedPassword = await hashPassword(password);
    const newUser = new User({ email, password: hashedPassword });
    const url = gravatar.url(email);
    newUser.avatarURL = url;
    newUser.verificationToken = nanoid();
    await newUser.save();
    const mailOptions = {
      from: process.env.NODEMAILER_USER,
      to: newUser.email,
      subject: "Verify your email",
      text:
        "http://localhost:3000/api/users/auth/verify/" +
        newUser.verificationToken,
    };

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log(error);
      } else {
        console.log("Email sent: " + info.response);
      }
    });
    return User.findOne({ email });
  } catch (e) {
    console.error(e);
  }
};

const login = async ({ email, password }) => {
  try {
    const user = await User.findOne({ email });
    if (!user || !comparePassword(password, user.password)) {
      return null;
    } else {
      if (!user.verify) {
        return null;
      }
      const token = jwt.sign({ ...user }, process.env.SECRET_KEY, {
        expiresIn: "1h",
      });
      await User.findOneAndUpdate({ _id: user.id }, { $set: { token: token } });
      return await User.findOne({ email });
    }
  } catch (e) {
    console.error(e);
  }
};

const logout = async id => {
  try {
    return await User.findOneAndUpdate({ _id: id }, { $set: { token: null } });
  } catch (e) {
    console.error(e);
  }
};

const verifyToken = async verificationToken => {
  try {
    return User.findOneAndUpdate(
      { verificationToken: verificationToken },
      { $set: { verificationToken: null, verify: true } }
    );
  } catch (e) {
    console.error(e);
  }
};

const verifyAgain = async email => {
  try {
    const user = await User.findOne({ email });
    if (user.verify) {
      return null;
    } else {
      const mailOptions = {
        from: process.env.NODEMAILER_USER,
        to: user.email,
        subject: "Verify your email",
        text:
          "http://localhost:3000/api/users/auth/verify/" +
          user.verificationToken,
      };
      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
        } else {
          console.log("Email sent: " + info.response);
        }
      });
      return user;
    }
  } catch (e) {
    console.error(e);
  }
};

module.exports = {
  register,
  getUserByEmail,
  login,
  logout,
  verifyToken,
  verifyAgain,
};
