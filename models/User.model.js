//imports
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

//mongoose schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  userNumber: {
    type: String,
  },
  password: {
    type: String,
    required: true,
  },
  info: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
});

//hash password before saving account
userSchema.pre("save", function (next) {
  const user = this;
  if (!user.isModified("password")) {
    return next();
  }

  const saltRounds = 10;
  bcrypt.genSalt(saltRounds, (err, salt) => {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, (err, hash) => {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

//compare password while loging in
userSchema.methods.comparePassword = function (userPassword) {
  const user = this;
  return new Promise((resolve, reject) => {
    bcrypt.compare(userPassword, user.password, (err, match) => {
      if (err) return reject(err);
      if (!match) return reject(err);
      resolve(true);
    });
  });
};

mongoose.model("User", userSchema);
