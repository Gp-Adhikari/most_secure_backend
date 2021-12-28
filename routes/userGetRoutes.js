//imports
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

//get value form .env file
require("dotenv").config();

//middleware
const generateAccessToken = require("../middleware/generateAccessToken.middleware");
const verifyCookies = require("../middleware/verifyCookieToken.middleware");

//models
const User = mongoose.model("User");
const RefreshToken = mongoose.model("RefreshToken");

//get router from express
const router = express.Router();

//get csrfProtection token
router.get("/", (req, res) => {
  res.status(200).json({ status: true, csrfToken: req.csrfToken() });
});

//generate new token
router.post("/token", verifyCookies, (req, res) => {
  //   console.log(req.headers);

  try {
    jwt.verify(
      req.refreshToken,
      process.env.REFRESH_TOKEN_SECRET,
      (err, user) => {
        if (err)
          return res
            .status(403)
            .json({ status: false, message: "Unexpected Error." });

        const accessToken = generateAccessToken({ id: user.id });
        return res.json({ status: true, token: accessToken });
      }
    );
  } catch (error) {
    return res.json({ status: false, message: "Unexpected Error!" });
  }
});

module.exports = router;
