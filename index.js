require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');
const authRouter = require('./modules/auth/auth.router');

mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => {
    console.log('Connect DB successfully');
  })
  .catch(() => {
    console.log('Error connect DB');
  });

const app = express();

app.use(express.static('public'));
app.use(express.json());
app.use(
  cors({
    origin: ['http://localhost:3000'],
    credentials: true,
  }),
);
app.use(cookieParser());
app.use('/api/auth', authRouter);

app.listen(process.env.PORT || 8080, (err) => {
  if (err) {
    return console.log('Error start app', err);
  }
  console.log(`Server started successfully at ${process.env.PORT || 8080}`);
});

app.use((err, req, res, next) => {
  console.log(err.message);
  res.status(400).send({ success: false, message: err.message });
});

app.use('*', (req, res) => {
  res.status(404).send({ success: false, message: '404 not found' });
});
