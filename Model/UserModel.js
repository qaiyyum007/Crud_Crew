import mongoose from 'mongoose'

let UserSchema = new  mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  avatar:{
    type: String,
    default: 'https://res.cloudinary.com/devatchannel/image/upload/v1602752402/avatar/avatar_cugq40.png'
},


  

},{
    timestamps:true,
});

const User=mongoose.model("User", UserSchema);



export default User