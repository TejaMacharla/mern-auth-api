const express=require('express')
const morgan=require('morgan')
const cors=require('cors')
const bodyParser=require('body-parser')
const mongoose=require('mongoose')
require('dotenv').config()


//const url=process.env.DATABASE
const app=express()
//app middlewares
app.use(morgan('dev'))
//import routes
const authRoutes=require('./routes/auth')
const userRoutes=require('./routes/user')
//app.use(cors())//allows all origins
if((process.env.NODE_ENV='development')){
    app.use(cors({origin:`http://localhost:3000`}))
}
app.use(bodyParser.json())
//middleware
app.use('/api',authRoutes)
app.use('/api',userRoutes)
const port=process.env.PORT || 8500;
app.listen(port,(err)=>{
    if(err)throw err;
   console.log(`server is running on ${port}`)
})
//db connection
const config = {
    autoIndex: true,
    useNewUrlParser:true,
    useFindAndModify: false,
    useUnifiedTopology: true,
    useCreateIndex:true
};
return mongoose.connect(process.env.DATABASE, {config})
.then(()=>console.log('DB Connected'))
.catch(err=>console.log('DB Connection Error:',err))


