const { UserModel } = require('./user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const register = async (req, res) => {
  const { username, password } = req.body;
  const existedUser = await UserModel.findOne({ username });

  if (existedUser) throw new Error('Username existed');

  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(password, salt);

  const newUser = await UserModel.create({
    username,
    password: hashPassword,
  });

  res.send({
    success: true,
    data: newUser,
  });
};

const login = async (req, res) => {
  const { username, password } = req.body;
  const existedUser = await UserModel.findOne({ username });

  if (!existedUser) throw new Error('Wrong username or password');

  const matched = await bcrypt.compare(password, existedUser.password);

  if (!matched) throw new Error('Wrong username or password');

  const userID = existedUser._id;

  const { access_token, refresh_token } = getNewTokens({ userID });

  res.cookie('refresh_token', refresh_token, {
    expires: new Date(Date.now() + 1000 * 60),
    httpOnly: true,
  });

  res.send({
    success: true,
    data: {
      userID,
      access_token,
    },
  });
};

const getUserData = async (req, res) => {
  const { user } = req;
  
  res.send({
    success: true,
    data: user,
  });
};

const getNewTokens = (data) => {
  const access_token = jwt.sign(data, process.env.SECRET_KEY, {
    expiresIn: 5,
  });

  const refresh_token = jwt.sign(data, process.env.SECRET_KEY, {
    expiresIn: 20,
  });

  return {
    access_token,
    refresh_token,
  };
};

const renewAccessToken = async (req, res) => {
  const { user } = req;
  const { access_token, refresh_token } = getNewTokens({ userID: user._id });

  res.cookie('refresh_token', refresh_token, {
    expires: new Date(Date.now() + 1000 * 60),
    httpOnly: true,
  });

  res.send({
    success: true,
    data: {
      access_token,
    },
  });
};

module.exports = {
  register,
  login,
  getUserData,
  renewAccessToken,
};
