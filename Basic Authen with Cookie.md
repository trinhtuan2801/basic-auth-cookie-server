## Server side

**package.json**

```
"dev": "nodemon index"
```

```
"bcryptjs": "^2.4.3",
"cookie-parser": "^1.4.6",
"cors": "^2.8.5",
"dotenv": "^16.3.1",
"express": "^4.18.2",
"jsonwebtoken": "^9.0.2",
"mongoose": "^8.0.1",
"nodemon": "^3.0.1"
```

**index.js**

```
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const authRouter = require('./modules/auth/auth.router');
```

```
mongoose.connect(process.env.MONGODB_URI)
.then().catch()
```

```
const app = express();

app.use(express.static('public'));
app.use(express.json());
app.use(cors({ origin: ['http://localhost:3000'], credentials: true }));
app.use(cookieParser());
app.use('/api/auth', authRouter);
```

```
app.listen(process.env.PORT || 8080, (err) => {
  if (err) {
    return console.log('Error start app', err);
  }
  console.log(`Server started successfully at ${process.env.PORT || 8080}`);
});
```

```
app.use((err, req, res, next) => {
  res.status(400).send({ success: false, message: err.message });
});

app.use('*', (req, res) => {
  res.status(404).send({ success: false, message: '404 not found' });
});
```

**user.js**

```
const mongoose = require('mongoose')

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true }
}, { timestamps: true })

const UserModel = mongoose.model('User', UserSchema)

module.exports = { UserModel, UserSchema }
```

**needAuthenticated.js**

```
const { UserModel } = require('../modules/auth/user');
const jwt = require('jsonwebtoken');

const needAuthenticated = async (req, res, next) => {
  try {
    const token = req.headers.authorization;
    if (!token) throw new Error('Token not found');

    const jwtToken = token.split(' ')[1];
    const data = jwt.verify(jwtToken, process.env.SECRET_KEY);
    const { userID } = data;

    if (!userID) throw new Error("User's ID not found");
    const existedUser = await UserModel.findById(userID);

    if (!existedUser) throw new Error('User not found');
    req.user = existedUser;

    next();
  } catch (err) {
    res.status(401).send({ success: false, message: err.message });
  }
};
module.exports = needAuthenticated;
```

**verifyRefreshToken**

```
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

```

**auth.router.js**

```
const express = require('express');
const router = express.Router();
const authController = require('./auth.controller');
const needAuthenticated = require('../../middlewares/needAuthenticated');
const verifyRefreshToken = require('../../middlewares/verifyRefreshToken');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.get('/user', needAuthenticated, authController.getUserData);
router.get('/access-token', verifyRefreshToken, authController.renewAccessToken);
module.exports = router;
```

**auth.controller.js**

```
const { UserModel } = require('./user');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const register = async (req, res) => {
  const { username, password } = req.body;
  const existedUser = await UserModel.findOne({ username });

  if (existedUser) throw new Error('Username existed');

  const salt = await bcrypt.genSalt(10);
  const hashPassword = await bcrypt.hash(password, salt);

  const newUser = await UserModel.create({ username, password: hashPassword });

  res.send({ success: true, data: newUser });
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

  res.send({ success: true, data: { userID, access_token }});
};

const getUserData = async (req, res) => {
  const { user } = req;
  res.send({ success: true, data: user });
};

const getNewTokens = (data) => {
  const access_token = jwt.sign(data, process.env.SECRET_KEY, { expiresIn: 5 });

  const refresh_token = jwt.sign(data, process.env.SECRET_KEY, { expiresIn: 20 });

  return { access_token, refresh_token };
};

const renewAccessToken = async (req, res) => {
  const { user } = req;
  const { access_token, refresh_token } = getNewTokens({ userID: user._id });

  res.cookie('refresh_token', refresh_token, {
    expires: new Date(Date.now() + 1000 * 60),
    httpOnly: true,
  });

  res.send({ success: true, data: { access_token }});
};

module.exports = {
  register,
  login,
  getUserData,
  renewAccessToken,
};

```
