import  express from 'express'
const expressRouter=express.Router()
import   bcrypt from 'bcrypt'
import {isAuth,generateToken} from '../middleware/auth.js'
import sgMail from'@sendgrid/mail';

import   jwt  from'jsonwebtoken'
import User from '../Model/UserModel.js';

// use here  your Mail Key 
sgMail.setApiKey(process.env.MAIL_KEY);


class AuthRouter{
    authRouter
    constructor(){
     this.authRouter=expressRouter
     this.authRouter.post('/registration' ,async(req,res)=>{
        try {
            const {name,email,password}=req.body

             const exitsUser= await User.findOne({email})
             if(exitsUser){
                 return res.send("email alreday exits")
             }
             const hasedPassword= await bcrypt.hash(password,12)

             const newUser = new User({
                name, email, password: hasedPassword
            })


            const activation_token = jwt.sign(newUser.toJSON(), process.env.ACTIVATION_TOKEN_SECRET, {
                expiresIn: 604800 // 1 week
              });

            

                    
            const emailData = {
                from: process.env.EMAIL_FROM,
                to: process.env.EMAIL_TO,
                subject: 'Account activation link',
      
                html: `
                            <h1>Please use the following to activate your account</h1>
                           <p>${process.env.CLIENT_URL}/users/activate/${activation_token}</p>
                           <hr />
                             <p>This email may containe sensetive information</p>
                           <p>${process.env.CLIENT_URL}</p>
                  `
              };
               await sgMail.send(emailData, "Verify your email address")

             return   res.json({msg: "Register Success! Please activate your email to start."})

        } catch (err) {
            return res.status(500).send(`${err.message}-${err.stack}`)
        }
      
       
     })


     this.authRouter.post('/activate',   async (req, res) => {

        try {
          const {activation_token} = req.body
          const user = jwt.verify(activation_token, process.env.ACTIVATION_TOKEN_SECRET)
  
          const {name, email, password} = user
  
          const check = await User.findOne({email})
          if(check) return res.status(400).json({msg:"This email already exists."})
  
          const newUser = new User({
              name, email, password
          })
  
          await newUser.save()
  
          res.json({msg: "Account has been activated!"})
  
      } catch (err) {
          return res.status(500).json({msg: err.message})
      }
      })



     this.authRouter.post('/login' ,async(req,res)=>{

        try {
            
            const {email,password}=req.body

             const user= await User.findOne({email})
             if(!user){
                 return res.status(404).send("email does not exits")
             }
             const isMatch = await bcrypt.compare(password, user.password)
             if(!isMatch) return res.status(400).json({msg: "Incorrect password."})

             const token=jwt.sign({
                 _id:user._id,
                 "email":user.email,
                 "name":user.fullName,
                 
                 "password":user.password,
            },process.env.ACCESS_TOKEN_SECRET,{expiresIn:"1h"})
             return res.status(200).send({
                 token
               
             })


        } catch (err) {
            return res.status(500).send(`${err.message}-${err.stack}`)
        }
     })

// get Single User


     this.authRouter.get('/singleUser/:id' ,isAuth ,async(req,res)=>{

        try {
            const user = await User.findById(req.params.id);
           const { password, id, ...others } = user._doc;
            return res.send({others})

        } catch (err) {
            return res.status(500).send(`${err.message}-${err.stack}`)
        }
     })

 // get All user


     this.authRouter.get('/all_user', isAuth,async(req,res)=>{

        try {
            const users = await User.find();
            return res.send(users)

        } catch (err) {
            return res.status(500).send(`${err.message}-${err.stack}`)
        }
     })


 // get Profile of user

     this.authRouter.get('/profile/:id',isAuth ,async(req,res)=>{

        try {
            const user = await User.findById(req.user._id)
            if (user) {
                res.send({
                  _id: user._id,
                  name: user.name,
                  email: user.email,
                })
            }else {
                return res.status(404).send(" user is not found")
            }

            return res.status(200).send(user)

        } catch (err) {
            return res.status(500).send(`${err.message}-${err.stack}`)
        }
     })

// update profile User



     this.authRouter.put('/update_profile/:id',isAuth ,async(req,res)=>{

        try {
            const user = await User.findById(req.user._id)
            if (user) {
                user.email = req.body.email || user.email
                user.name = req.body.name || user.name

                const updatedUser = await user.save()

                res.send({
                  _id: user._id,
                  password: user.password,
                  name: user.userName,
                  email: user.email,
                  token: generateToken(user._id),
                })
            }else {
                return res.send(" user is not found")
            }

            return res.status(200).send(updatedUser)

        } catch (err) {
            return res.status(500).send(`${err.message}-${err.stack}`)
        }
     })



     


// change the user Password


     this.authRouter.put('/change_Password/:id' ,async(req,res)=>{

        try {
            const {password}=req.body
            const hasedPassword= await bcrypt.hash(password,10)
            const resetPassword=   await User.findOneBy(req.params.id, {
                password: hasedPassword
            })
            return res.status(201).send("password change Suceesfull", resetPassword )

        } catch (err) {
            return res.status(500).send(`${err.message}-${err.stack}`)
        }
     })


   


    }
}

export default AuthRouter