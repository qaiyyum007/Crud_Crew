import mongoose from 'mongoose'


const ConnectDB=async()=>{
    try {

        mongoose.connect(process.env.MONGO_URL,{
            useCreateIndex:true,
            useNewUrlParser:true,
            useUnifiedTopology:true,
            useNewUrlParser:true
        })

        console.log("DataBase is connected")
        
    } catch (error) {
        console.log("DataBase is connection failed")
        process.exit(1)

    }
    
}

export default ConnectDB
