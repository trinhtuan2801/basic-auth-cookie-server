const { UserModel } = require('../modules/auth/user');
const jwt = require('jsonwebtoken');

const verifyRefreshToken = async (req, res, next) => {
  try {
    const refresh_token = req.cookies.refresh_token;
    if (!refresh_token) throw new Error();
    const data = jwt.verify(refresh_token, process.env.SECRET_KEY);
    const { userID } = data;
    const existedUser = await UserModel.findById(userID);
    req.user = existedUser;
    next();
  } catch (error) {
    res.status(401).send({ success: false, message: 'You need to login' });
  }
};

module.exports = verifyRefreshToken;
