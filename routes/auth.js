const express = require('express');
const router=express.Router()
//import controllers 
const {signup,accountActivation,signin,forgotPassword,resetPassword,googleLogin,facebookLogin} = require('../controller/auth')
//import validators 
const {userSignupValidator,
       userSigninValidator,
       forgotPasswordValidator,
       resetPasswordValidator}=require('../validators/auth')
const {runValidation}=require('../validators')
router.post('/signup',userSignupValidator,runValidation,signup)
router.post('/account-activation',accountActivation)
router.post('/signin',userSigninValidator,runValidation,signin)
//forgot and reset password validator routes
router.put('/forgot-password',forgotPasswordValidator,runValidation,forgotPassword)
router.put('/reset-password',resetPasswordValidator,runValidation,resetPassword)
//google and facebook routes
router.post('/google-login',googleLogin)
router.post('/facebook-login',facebookLogin)
module.exports = router//{}