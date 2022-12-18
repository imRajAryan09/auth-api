const { validate } = require("deep-email-validator");

exports.isEmailValid = async (email) => await validate(email);
