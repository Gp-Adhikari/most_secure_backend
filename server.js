const express = require("express");
const limitter = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const helmet = require("helmet");
const csrf = require("csurf");
const cors = require("cors");

//built in modules
const cluster = require("cluster");
const os = require("os");

//get number of cpus
const numCpu = os.cpus().length;

require("dotenv").config();

const app = express();

app.use(
  cors({
    credentials: true,
    origin: ["http://localhost:3000", "*"],
    // exposedHeaders: ["set-cookie"],
  })
);

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Credentials", true);
  res.header("Access-Control-Allow-Origin", req.headers.origin);
  res.header(
    "Access-Control-Allow-Methods",
    "GET,PUT,POST,DELETE,UPDATE,OPTIONS"
  );
  res.header(
    "Access-Control-Allow-Headers",
    "X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept"
  );
  next();
});

//get json data
app.use(bodyParser.json());
// app.use(bodyParser.urlencoded({ extended: false }));

//access cookie easy
app.use(
  cookieParser({
    cookie: {
      // sameSite: "none",
      httpOnly: true,
      // secure: true,
    },
  })
);

//csrf protection
// app.use(csrf({ cookie: { sameSite: "strict" } }));
app.use(
  csrf({
    cookie: {
      // domain: "https://localhost:3000",
      // sameSite: "none",
      httpOnly: true,
      // secure: true,
    },
  })
);

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
  // console.log("connected");
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

//if the cluster is master
if (cluster.isMaster) {
  for (let i = 0; i < numCpu; i++) {
    cluster.fork();
  }

  //if worker dies or is killed
  cluster.on("exit", (worker, code, signal) => {
    cluster.fork();
  });
} else {
  app.listen(8080, () => {
    console.log("Port: " + 8080, process.pid);
  });
}

// app.listen(8080, () => {
//   console.log("Port: " + 8080);
// });
