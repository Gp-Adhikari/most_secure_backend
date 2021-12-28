const express = require("express");
const limitter = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const helmet = require("helmet");
const csrf = require("csurf");

require("dotenv").config();

const app = express();

//get json data
app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({ extended: false }));

//access cookie easy
app.use(cookieParser());

//csrf protection
app.use(csrf({ cookie: true }));

//using helmet for security
app.use(helmet());

//prevent ddos and bruteforce
app.use(
  limitter({
    windowMs: 10 * 1000, //10 sec
    max: 5, // 5 requests
    message: {
      code: 429,
      message: "Too many requests, Please try again later",
      status: false,
    },
  })
);

//connecting to mongodb
mongoose.connect(process.env.URI);

//on connection
mongoose.connection.on("connected", () => {
  console.log("connected");
});

//on error
mongoose.connection.on("error", () => {
  console.log("Server Not Found");
});

//models
require("./models/User.model");
require("./models/Otp.model");
require("./models/RefreshToken.model");

//routes
const userAuthRoutes = require("./routes/userAuthRoutes");
const userGetRoutes = require("./routes/userGetRoutes");

app.use(userAuthRoutes);
app.use(userGetRoutes);

//if any syntax error occurs
app.use(function (err, req, res, next) {
  if (err.code === "EBADCSRFTOKEN") {
    // handle CSRF token errors here
    res.status(403);
    return res.json({ status: false, message: "Not a valid address." });
  }

  return res
    .status(err.status || 500)
    .json({ status: false, message: "Syntax Error!" });
});

app.listen(8080, () => {
  console.log("Port: " + 8080);
});
