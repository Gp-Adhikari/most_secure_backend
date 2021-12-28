//imports
const mongoose = require("mongoose");

//mongoose schema
const otpSchema = new mongoose.Schema({
  code: {
    type: Number,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    // default: new Date().getTime() + 300 * 1000,
    default: Date.now(),
    index: {
      expires: "5m",
    },
  },
});

mongoose.model("Otp", otpSchema);
