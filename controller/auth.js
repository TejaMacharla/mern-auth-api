const User=require('../models/user')
const jwt=require('jsonwebtoken')
const expressJwt=require('express-jwt')
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const _=require('lodash')
const sgMail=require('@sendgrid/mail')
const {OAuth2Client}=require('google-auth-library')
sgMail.setApiKey(process.env.SENDGRID_API_KEY)

// exports.signup=(req,res)=>{
//    // console.log('req body on signup',req.body)
//     const{name,email,password}=req.body

//     User.findOne({email}).exec((err, user)=>{
//         if(user){
//             return res.status(400).json({
//                 message:'Email is taken'
//             })
//         }
//     })
//     let newUser=new User({name,email,password})
//     newUser.save((err,success)=>{
//         if(err){
//             console.log('Signup Error',err)
//             return res.status(400).json({
//                 error: err
//             })
//         }
//         res.json({
//             message:'Signup success..! Please Signin'
//         })
//     })
// }


exports.signup=(req,res)=>{
    // console.log('req body on signup',req.body)
    const{name,email,password}=req.body

    User.findOne({email}).exec((err, user)=>{
        if(user){
            return res.status(400).json({
                errors:'Email is taken'
            })
        }
        const token=jwt.sign({name,email,password},process.env.JWT_ACCOUNT_ACTIVATION,{expiresIn:'10m'})
        const emailData={
            from:process.env.EMAIL_FROM,
            to:email,
            subject:`Account activation link`,
            html:`
                   <h1>Please use the following link to activate your account</h1>
                   <p>${process.env.CLIENT_URL}/auth/activate/${token}</p>
                   <hr/>
                   <p>This email may contain sensetive information</p>
                   <p>${process.env.CLIENT_URL}</p>
                   `
        }
        sgMail.send(emailData).then(sent=>{
            //console.log('signup email sent',sent)
            return res.json({
                message:`Email has been sent to${email} following the instruction to activate your account`
            })
        })
    })
}

exports.accountActivation=(req,res)=>{
    const{token} = req.body
    if(token){
        jwt.verify(token,process.env.JWT_ACCOUNT_ACTIVATION,(err,decode)=>{
            if(err){
                console.log('JWT VERIFY ACCOUNT ACTIVATION ERROR', err)
                return res.status(401).json({
                    errors:'Expired link.Signup again'
                })
            }
            const {name,email,password}=jwt.decode(token)
            const user=new User({name,email,password})
            user.save((err,user)=>{
                if(err){
                    console.log('save user in account activation error',err)
                    return res.status(401).json({
                        errors:'Error saving user in database.Try signup again'
                    })
                }
                return res.json({
                    message:'Signup success.Please signin'
                })
            })
        })
    }else{
        return res.json({
            message:'Something went wrong. Please try again'
        })
    }
}

exports.signin=(req,res)=>{
    const{email,password}=req.body
    //check if user exist
    User.findOne({email}).exec((err,user)=>{
        if(err || !user){
            return res.status(400).json({
                errors:'User with that email does not exist.Please signup'
            })
        }
        //authenticate.
        if(!user.authenticate(password)){
            return res.status(400).json({
                errors:'Email and Password do not match'
            })
        }
        //generate a token and send to cliet
        const token=jwt.sign({_id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'})
        const {_id,name,email,role}=user
        return res.json({
            token,
            user:{_id,name,email,role}
        })
    })
}

exports.requireSignin=expressJwt({
    secret: process.env.JWT_SECRET,
    algorithms: ['sha1', 'RS256', 'HS256'],
})

exports.adminMiddleware=(req,res,next)=>{
    User.findById({_id:req.user._id}).exec((err,user)=>{
        if(err||!user){
            return res.status(400).json({
                errors:'User not found'
            })
        }
        if(user.role!=='admin'){
            return res.status(400).json({
                errors:'Admin resource.access denied'
            })
        }
        req.profile=user
        next()
    })
}

exports.forgotPassword=(req,res)=>{
    const {email}=req.body
    User.findOne({email},(err,user)=>{
        if(err||!user){
            return res.status(400).json({
                errors:'User with that email does not exist'
            })
        }

        const token=jwt.sign({_id:user._id,name:user.name},process.env.JWT_RESET_PASSWORD,{expiresIn:'10m'})
        const emailData={
            from:process.env.EMAIL_FROM,
            to:email,
            subject:`Password rest link`,
            html:`
                   <h1>Please use the following link to reset your password</h1>
                   <p>${process.env.CLIENT_URL}/auth/password/reset/${token}</p>
                   <hr/>
                   <p>This email may contain sensetive information</p>
                   <p>${process.env.CLIENT_URL}</p>
                   `
        }
        return user.updateOne({resetPasswordLink:token},(err,success) => {
            if(err){
                console.log('reset password link error',err)
                return res.status(400).json({
                    errors:'Database connection error on user password forgot request'
                })
            }else{
                sgMail.send(emailData).then(sent=>{
                    //console.log('signup email sent',sent)
                    return res.json({
                        message:`Email has been sent to ${email} following the instruction to reset the password`
                    })
                })
                .catch(err => {
                    return res.json({
                        message:err.message
                    })
                })
            }
        })
        

    })
}

exports.resetPassword=(req,res) => {
    const{resetPasswordLink,newPassword}=req.body
    if(resetPasswordLink){
        jwt.verify(resetPasswordLink,process.env.JWT_RESET_PASSWORD,function(err,decode){
            if(err){
                return res.status(400).json({
                    errors:'Expired link.Try again later.'
                })
            }
            User.findOne({resetPasswordLink},(err,user)=>{
                if(err||!user){
                    return res.status(400).json({
                        errors:'Something went wrong.Try again later.'
                    })
                }
                const updatedFields={
                    password:newPassword,
                    resetPasswordLink:''
                }
                user=_.extend(user,updatedFields)
                user.save((err,result)=>{
                    if(err){
                        return res.status(400).json({
                            errors:'Error resetting user password.Try again later.'
                        })
                    }
                    res.json({
                        message:'Great! now you can login with your new password.'
                    })
                })
            })
           
        })
    }
}


const client=new OAuth2Client(process.env.GOOGLE_CLIENT_ID)
exports.googleLogin=(req,res)=>{
    const {idToken}=req.body
    
    client.verifyIdToken({idToken,audience:process.env.GOOGLE_CLIENT_ID}).then(response=>{
        const {email_verified,name,email}=response.payload
        if(email_verified){
            User.findOne({email}).exec((err,user)=>{
                if(user){
                    const token=jwt.sign({_id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'})
                    const{_id,name,email,role}=user
                    return res.json({
                        token,user:{_id,name,email,role}
                    })
                }else{
                    let password=email+process.env.JWT_SECRET
                    user=new User({name,email,password})
                    user.save((err,data)=>{
                        if(err){
                            console.log('ERROR GOOGLE LOGIN ON USER SAVE',err)
                            return res.status(400).json({
                                errors:'User signup failed with google'

                            })
                        }
                        const token=jwt.sign({_id:data._id},process.env.JWT_SECRET,{expiresIn:'7d'})
                    const{_id,name,email,role}=data
                    return res.json({
                        token,user:{_id,name,email,role}
                    })
                    })
                }
            })
        }else{
            return res.status(400).json({
                errors:'User google login failed.Try again later.'

            })
        }
    })
}

exports.facebookLogin=(req,res)=>{
   console.log('FACEBOOK LOGIN REQBODY',req.body) 
   const {userID,accessToken}=req.body
   const url=`https://graph.facebook.com/v2.11/${userID}/?fields=id,name,email&access_token=${accessToken}`
   return(
       fetch(url,{
           method:'GET'
       })
       .then(response=>response.json())
       //.then(response=>console.log(response.json()))
       .then(response=>{
           const{email,name}=response
           User.findOne({email}).exec((err,user)=>{
            if(user){
                const token=jwt.sign({_id:user._id},process.env.JWT_SECRET,{expiresIn:'7d'})
                const{_id,name,email,role}=user
                return res.json({
                    token,user:{_id,name,email,role}
                })
            }else{
                let password=email+process.env.JWT_SECRET
                    user=new User({name,email,password})
                    user.save((err,data)=>{
                        if(err){
                            console.log('ERROR FACEBOOK LOGIN ON USER SAVE',err)
                            return res.status(400).json({
                                errors:'User signup failed with facebook'

                            })
                        }
                        const token=jwt.sign({_id:data._id},process.env.JWT_SECRET,{expiresIn:'7d'})
                    const{_id,name,email,role}=data
                    return res.json({
                        token,user:{_id,name,email,role}
                    })
                    })
            }
           })
       }).catch(error=>{
           res.json({
               errors:'Facebook login failed.Try again later.'
           })
       })

   )
}