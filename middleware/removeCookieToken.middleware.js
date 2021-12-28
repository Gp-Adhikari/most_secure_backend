const mongoose = require("mongoose");
const RefreshToken = mongoose.model("RefreshToken");

const getAppCookies = (req) => {
  // We extract the raw cookies from the request headers
  const rawCookies = req.headers.cookie.split("; ");
  // rawCookies = ['myapp=secretcookie, 'analytics_cookie=beacon;']

  const parsedCookies = {};
  rawCookies.forEach((rawCookie) => {
    const parsedCookie = rawCookie.split("=");
    // parsedCookie = ['myapp', 'secretcookie'], ['analytics_cookie', 'beacon']
    parsedCookies[parsedCookie[0]] = parsedCookie[1];
  });
  return parsedCookies;
};

const removeCookies = (req, res, next) => {
  try {
    RefreshToken.findOneAndDelete(
      { refreshToken: String(getAppCookies(req).token) },
      (err, refreshTokenDetails) => {
        if (err)
          return res.status(400).json({
            status: false,
            message: "Unexpected Error or cookie is missing!",
          });
        next();
      }
    );

    next();
  } catch (error) {
    return res.status(400).json({
      status: false,
      message: "Unexpected Error or cookie is missing!",
    });
  }
};

module.exports = removeCookies;
