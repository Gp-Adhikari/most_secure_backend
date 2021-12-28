//imports
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

//get value form .env file
require("dotenv").config();

//middleware
const validateEmail = require("../middleware/validateEmail.middleware");
const generateAccessToken = require("../middleware/generateAccessToken.middleware");
const removeCookies = require("../middleware/removeCookieToken.middleware");

//models
const User = mongoose.model("User");
const RefreshToken = mongoose.model("RefreshToken");
const Otp = mongoose.model("Otp");

//get router from express
const router = express.Router();

//login route for user
router.post("/login", validateEmail, async (req, res) => {
  //getting email and password
  const { email, password } = req.body;

  //check if password is empty
  if (!password)
    return res
      .status(422)
      .json({ status: false, message: "Incorrect Email or password" });

  if (password.length < 8)
    return res
      .status(422)
      .json({ status: false, message: "Incorrect Email or password" });

  //if everything is ok
  //search for the user
  const userData = await User.findOne({ email: String(email) });

  //if any error
  if (!(await userData))
    return res
      .status(400)
      .json({ status: false, message: "User doesn't exist!" });

  //if the user exists
  try {
    //compare user saved password and provided password
    await userData.comparePassword(String(password));

    //generate access tokem
    const accessToken = generateAccessToken({ id: userData._id });

    //generate refresh token for 30 days
    const refreshToken = jwt.sign(
      { id: userData._id },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: "30d",
      }
    );
    //check if the refresh token exists
    RefreshToken.findOne(
      { email: String(email) },
      async (err, existingRefreshToken) => {
        //if any error
        if (err) {
          return res
            .status(400)
            .json({ status: false, message: "Unexpected Error!" });
        }

        //if the refresh token already exists on database
        if (existingRefreshToken !== null) {
          //set the existing refresh token as http only cookie
          res.cookie("token", existingRefreshToken.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production" ? true : false,
            maxAge: 1000 * 60 * 60 * 24 * 30,
          });

          //send the access token to the user
          return res.status(201).json({
            token: accessToken,
            status: true,
          });
        } else {
          //if the refresh token doesn't exist in the database
          //set the refresh token to database
          await new RefreshToken({
            refreshToken: refreshToken,
            email: email,
          }).save();

          //set refresh token as httponly cookie
          res.cookie("token", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production" ? true : false,
            maxAge: 1000 * 60 * 60 * 24 * 30,
          });

          //send the access token
          return res.status(201).json({
            token: accessToken,
            status: true,
          });
        }
      }
    );
  } catch (error) {
    //if the user doesnt exists
    return res
      .status(400)
      .json({ status: false, message: "User doesn't exist!" });
  }
});

//signup route for user
router.post("/signup", validateEmail, async (req, res) => {
  //getting values from body
  const { username, email, password, confirmPassword } = req.body;

  //checking if the values are empty
  if (!username || !email || !password || !confirmPassword)
    return res.status(422).json({ status: false, message: "Missing field." });

  //checking if username is less than 3 characters
  if (username.length < 3)
    return res.status(422).json({
      status: false,
      message: "Name must be at least 3 characters.",
    });

  //checking if password or confirmpassword are empty
  if (password === "" || confirmPassword === "")
    return res
      .status(422)
      .json({ status: false, message: "Password field is empty." });

  //checking if password or confirmpassword has less than 8 characters
  if (password.length < 8 || confirmPassword.length < 8)
    return res.status(422).json({
      status: false,
      message: "Password must be at least 8 characters.",
    });

  //checking if password or confirmpassword are same
  if (password !== confirmPassword)
    return res
      .status(422)
      .json({ status: false, message: "Password didn't match." });

  //search for the user
  User.findOne({ email: String(email) }, async (err, userExists) => {
    //if user exists or some error
    if (err || userExists) {
      return res
        .status(400)
        .json({ status: false, message: "User Already Exists!" });
    }

    Otp.findOne({ email: String(email) }, async (err, data) => {
      if (err) return res.status(400).json("Unexpected Error!");

      //if the code exists
      try {
        //transfer email
        let transporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 587,
          secure: false,
          requireTLS: true,
          auth: {
            user: process.env.EMAIL,
            pass: process.env.PASSWORD,
          },
        });

        //mailing option
        let mailOptions = {
          from: process.env.EMAIL,
          to: req.body.email,
          subject: "Verification Code",
          text: `Thanks for using our platform!\nThe code is ${data.code}`,
        };

        //send the mail
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            return res
              .status(400)
              .json({ status: false, message: "Email doesn't exists!" });
          }

          return res
            .status(200)
            .json({ status: true, message: "Code sent Successfully!" });
        });
      } catch (error) {
        //if the code doesnt exists in the database with that email
        //generate code max_length = 6
        const otpCode = Math.floor(100000 + Math.random() * 900000);

        //create code data
        const otpData = new Otp({
          code: otpCode,
          email: req.body.email,
        });

        //save code data
        await otpData.save();
        //transfer email
        let transporter = nodemailer.createTransport({
          host: "smtp.gmail.com",
          port: 587,
          secure: false,
          requireTLS: true,
          auth: {
            user: process.env.EMAIL,
            pass: process.env.PASSWORD,
          },
        });

        //mailing option
        let mailOptions = {
          from: process.env.EMAIL,
          to: req.body.email,
          subject: "Verification Code",
          text: `Thanks for using our platform!\nThe code is ${otpCode}`,
        };

        //send the mail
        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            return res
              .status(400)
              .json({ status: false, message: "Email doesn't exists!" });
          }

          return res
            .status(200)
            .json({ status: true, message: "Code sent Successfully!" });
        });
      }
    });
  });
});

//signup route for user to enter the code
router.post("/signup/code", validateEmail, (req, res) => {
  const { username, email, password, confirmPassword, code } = req.body;

  //checking if the values are empty
  if (!username || !email || !password || !confirmPassword)
    return res.status(422).json({ status: false, message: "Missing field." });

  //checking if username is less than 3 characters
  if (username.length < 3)
    return res.status(422).json({
      status: false,
      message: "Name must be at least 3 characters.",
    });

  //checking if password or confirmpassword are empty
  if (password === "" || confirmPassword === "")
    return res
      .status(422)
      .json({ status: false, message: "Password field is empty." });

  //checking if password or confirmpassword has less than 8 characters
  if (password.length < 8 || confirmPassword.length < 8)
    return res.status(422).json({
      status: false,
      message: "Password must be at least 8 characters.",
    });

  //checking if password or confirmpassword are same
  if (password !== confirmPassword)
    return res
      .status(422)
      .json({ status: false, message: "Password didn't match." });

  //search for the user
  User.findOne({ email: String(email) }, async (err, userExists) => {
    //if user exists or some error
    if (err || userExists) {
      return res
        .status(400)
        .json({ status: false, message: "User Already Exists!" });
    }

    //get otp code with that email
    Otp.findOne({ email: String(email) }, async (err, data) => {
      //if err
      if (err)
        return res
          .status(400)
          .json({ status: false, message: "Unexpected Error!" });

      //if data is undefined or it doesnt exist
      if (data === undefined || data === null)
        return res
          .status(200)
          .json({ status: false, message: "Code Expired!" });
      //if data exists and matches the code
      if (parseInt(code) === data.code) {
        //save the user to database
        const user = new User({
          username: String(username),
          email: String(email),
          password: String(password),
        });

        await user.save();

        //clear the otp code
        await Otp.findByIdAndDelete(data._id);

        //generate access tokem
        const accessToken = generateAccessToken({ id: user._id });

        //generate refresh token for 30 days
        const refreshToken = jwt.sign(
          { id: user._id },
          process.env.REFRESH_TOKEN_SECRET,
          {
            expiresIn: "30d",
          }
        );

        //search if the refresh token already exists
        RefreshToken.findOne({ email: String(email) }, async (err, token) => {
          //if any error
          if (err)
            return res
              .status(400)
              .json({ status: false, message: "Unexpected Error!" });

          //if the refresh token already exists for that user
          try {
            //set the existing refresh token as http only cookie
            res.cookie("token", token.refreshToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === "production" ? true : false,
              maxAge: 1000 * 60 * 60 * 24 * 30,
            });

            //send the access token to the user
            return res.status(201).json({
              token: accessToken,
              status: true,
            });
          } catch (error) {
            //if the refresh token doesnt exists for that user

            //set the refresh token to database
            await new RefreshToken({
              refreshToken: refreshToken,
              email: email,
            }).save();

            //set refresh token as httponly cookie
            res.cookie("token", refreshToken, {
              httpOnly: true,
              secure: process.env.NODE_ENV === "production" ? true : false,
              maxAge: 1000 * 60 * 60 * 24 * 30,
            });

            //send the access token
            return res.status(201).json({
              token: accessToken,
              status: true,
            });
          }
        });
      }
      //if code doesnt match
      else {
        return res
          .status(400)
          .json({ status: false, message: "Incorrect Code!" });
      }
    });
  });
});

//logout
router.delete("/logout", removeCookies, (req, res) => {
  //remove token cookie from user
  res.clearCookie("token");
  res.clearCookie("_csrf");
  //send message to user
  return res
    .status(200)
    .json({ status: true, message: "Logged out successfully!" });
});

module.exports = router;
