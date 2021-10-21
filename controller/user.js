const User=require('../models/user')

exports.read=(req,res)=>{
    const userId = req.params.id;
    User.findById(userId).exec((err,user)=>{
        if(err ||!user){
            return res.status(404).json({
                error:'User not found'
            })
        }
        user.hashed_password=undefined;
        user.salt=undefined;
        res.json(user)
    })
}

exports.update=(req,res)=>{
   // console.log('update user -req.user', req.user,'update data -req.body', req.body)
   const {name,password} = req.body
   User.findOne({_id:req.user._id},(err,user)=>{
       if(err ||!user){
           return res.status(400).json({
               errors:'User not found'
           })
       }
       if(!name){
           return res.status(400).json({
               errors:'Name is required'
           })
       }else{
           user.name=name
       }
       if(password){
           if(password.length<6){
               return res.status(400).json({
                   errors:'Password should be minimum 6 characters long'
               })
           }else{
               user.password=password
           }
       }
       user.save((err,updatedUser)=>{
           if(err){
               return res.status(400).json({
                   errors:'User update failed'
               })
           }
           updatedUser.hashed_password=undefined;
           updatedUser.salt=undefined
           res.json(updatedUser)
       })
   })
}