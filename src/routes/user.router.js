const { getAll, create, getOne, remove, update, verifyCode, login, getLoggedUser, resetPassword, verifyCodeRessetPassword } = require('../controllers/user.controllers');
const express = require('express');
const verifyJwt= require('../utils/verifyJWT')
const userRouter = express.Router();

userRouter.route('/users')
    .get(verifyJwt, getAll)
    .post(create);

userRouter.route('/users/login')
    .post(login)

userRouter.route('/users/me')
    .get(verifyJwt, getLoggedUser);

userRouter.route('/users/:id')
    .get(verifyJwt, getOne)
    .delete(verifyJwt, remove)
    .put(verifyJwt, update);

userRouter.route('/users/verify/:code')
    .get(verifyCode);

userRouter.route('/users/reset_password')
    .post(resetPassword);

userRouter.route('/users/reset_password/:code')
    .post(verifyCodeRessetPassword);


module.exports = userRouter; 