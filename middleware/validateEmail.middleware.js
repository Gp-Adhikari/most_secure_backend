const validateEmail = (req, res, next) => {
  //get email from body
  const { email } = req.body;

  //check if email is empty
  if (!email)
    return res
      .status(422)
      .json({ status: false, message: "Incorrect Email or password" });

  //email format checker
  const checkEmail = String(email)
    .toLowerCase()
    .match(
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/
    );

  //check if sent value is in format of email
  if (!checkEmail)
    return res
      .status(422)
      .json({ status: false, message: "Incorrect Email or password" });

  //if its in format of email
  next();
};

module.exports = validateEmail;
