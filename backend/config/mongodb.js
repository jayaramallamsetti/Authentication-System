import mongoose from "mongoose";

const connectDB = async () => {
  mongoose.connection.on('connected', ()=>console.log("Database Connected"))

  await mongoose.connect(`${process.env.MONGODB_URI}Mern-Auth`)
};

export default connectDB;


// function that helps us to connect with MongoDB database