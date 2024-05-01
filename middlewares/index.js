const { getToken } = require("../utils");
const jwt = require("jsonwebtoken");
const config = require("../app/config");
const User = require("../app/user/model");

function decodeToken() {
  return async function (req, res, next) {
    try {
      let token = getToken(req);

      if (!token) return next();

      req.user = await jwt.verify(token, config.secretkey);

      let user = await User.findOne({ token: { $in: [token] } });

      if (!user) {
        res.json({
          error: 1,
          message: "Your session is not valid",
        });
      }
    } catch (error) {
      if (error && error.name === "JsonWebTokenError") {
        return res.json({
          error: 1,
          message: error.message,
        });
      }
      next(error);
    }
    return next();
  };
}

module.exports = { decodeToken };
