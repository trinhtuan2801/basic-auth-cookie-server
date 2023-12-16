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
