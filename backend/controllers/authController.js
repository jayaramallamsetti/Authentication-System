import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';


// ------------ Controller func for user registration ---------------------
export const register = async (req,res) => {
  const {name, email, password} = req.body;

  if(!name || !email || !password){   // checking whether all these 3 details are available or not
    return res.json({success: false, message: 'Missing Details'})
  }

  try {

    const existingUser = await userModel.findOne({email})
  
    // checking whether the entered email already exists in our database, if it exists then success:false
    if (existingUser) {
      return res.json({success:false, message:"User already exists"})
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);  // password encription

    const user = new userModel({name, email, password: hashedPassword});
    await user.save();  // to store user in MongoDb database

    const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'})  // whenever a new user gets created in the mongodb database then in that user collection it will add one "_id" property   ................. i.e. we've created json web token using users id

    // After generating the token we've to send this token to users in the response and in the response we will add the cookie ------------ i.e. using the cookie we'll send this token

    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',   // i.e. secure will be 'true' for "production" environment and is 'false' for "development" environment 
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60* 1000  // i.e. adding 7 days of expiry time for cookie
    })

    // Sending welcome email
    const mailOptions = {
      from: process.env.SENDER_EMAIL,
      to: email,  // i.e. mail is sent to the user who have created the account
      subject: `Welcome to Auth-Website ${name}`,
      text: `Hi there, Iam Jayaram Allamsetti, Welcome to Authentication Website, Your account has been created successfully with email id: ${email}`
    }

    await transporter.sendMail(mailOptions);
    
    return res.json({success:true});

  } catch (error) {
    res.json({success: false, message: error.message})
  }
}


// ------------ Controller func for user login ---------------------
export const login = async (req,res) => {
  const {email, password} = req.body;

  if(!email || !password) {
    return res.json({success:false, message:"Enter the details"})
  }

  try {
    const user = await userModel.findOne({email});
    if(!user) {
      return res.json({success: false, message: 'Invalid email'})
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {  // if password entered by the user is not matching
      return res.json({success: false, message: 'Invalid password'})
    }

    const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'})
    res.cookie('token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',   // i.e. secure will be 'true' for "production" environment and is 'false' for "development" environment 
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60* 1000  // i.e. adding 7 days of expiry time for cookie
    })

    return res.json({success:true})

  } catch (error) {
    res.json({success: false, message: error.message})
  }
}

// ------------ Controller func for user logout ---------------------
export const logout = async (req,res) => {
  try {
    // from our response we are removing the token inorder to make logout 
    res.clearCookie('token', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',   // i.e. secure will be 'true' for "production" environment and is 'false' for "development" environment 
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
      maxAge: 7 * 24 * 60 * 60* 1000  // i.e. adding 7 days of expiry time for cookie
    })

    return res.json({success:true, message:"Logged Out"})

  } catch (error) {
    res.json({success: false, message: error.message})
  }
}

// ------------- Controller func to send verification OTP to Users Email -------------
export const sendVerifyOtp = async (req,res) => {
  try {
    
    const userId = req.userId;

    const user = await userModel.findById(userId);

    if (user.isAccountVerified) {
      return res.json({success: false, message: "Account Already verified"})
    }

    // to generate OTP we use Math.random()
    const otp = String(Math.floor( 100000 + Math.random()*900000 ))

    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000

    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,  // i.e. mail is sent to the user who have created the account
      subject: `Account Verification OTP of Auth-Website`,
      text: `Your OTP is ${otp}. Verify your account by pasting this OTP in Auth-Website`
    }
    await transporter.sendMail(mailOption);

    res.json({success: true, message: 'Verification OTP Sent on Email'})

  } catch (error) {
    res.json({success: false, message: error.message})
  }
}

// ------------ Controller func for Account verification after entering the OTP in website ---------------------
export const verifyEmail = async (req,res) => {
  const { otp } = req.body;    
  const userId = req.userId;
  
  // Here user will only enter the "otp" then how to get "userId" ==> We'll get the "userId" from the token, and the token is stored in the cookies, So we need a "MIDDLEWARE" that will get the "cookie" and from the "cookie" we'll get the token , using this token we get the "userId" 

  if(!userId || !otp){
    res.json({success: false, message: 'Missing Details'})
  }
  
  try {
    const user = await userModel.findById(userId);
    if(!user){
      return res.json({success: false, message: 'User Not Found'})
    }

    if(user.verifyOtp === '' || user.verifyOtp !== otp){
      return res.json({success: false, message: 'Invalid OTP'})
    }

    if(user.verifyOtpExpireAt < Date.now()){  // checking whether otp is expired or not
      return res.json({success: false, message: 'OTP expired'})
    }

    // if OTP is not expired then we will verify the users account
    user.isAccountVerified = true;
    // Re-setting the otp and its expiry to default values i.e. "", 0
    user.verifyOtp = ""
    user.verifyOtpExpireAt = 0

    await user.save();

    return res.json({success: true, message: 'Email Verified Successfully'})

  } catch (error) {
    res.json({success: false, message: error.message})
  }
}

// ------------ Api that will check whether user is logged-in or not i.e. (Check if user is authenticated)-------------------
export const isAuthenticated = async (req,res) => {
  try {
    return res.json({success: true })
  } catch (error) {
    res.json({success: false, message: error.message})    
  }
}

// Send Password Reset OTP
export const sendResetOtp = async (req, res) => {
  const {email} = req.body;

  if (!email) {
    return res.json({success:false, message: 'Email is required'})
  }

  try {
    
    const user = await userModel.findOne({email});
    if(!user){
      return res.json({success:false, message: 'User not found'})
    }

    // to generate OTP we use Math.random()
    const otp = String(Math.floor( 100000 + Math.random()*900000 ))

    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000    // expiry time is 15 mins for resetOtp

    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,  // i.e. mail is sent to the user who have created the account
      subject: 'Password Reset OTP',
      text: `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password.`
    };

    await transporter.sendMail(mailOption);

    return res.json({success: true, message: 'OTP sent to your email'})
    
  } catch (error) {
    return res.json({success: false, message: error.message})
  }
}

// Reset User Password using the Reset OTP 
export const resetPassword = async (req, res) => {
  const {email, otp, newPassword} = req.body;

  if (!email || !otp || !newPassword) {
    return res.json({success: false, message: 'Email, OTP, and new Password are required'});
  }

  try {
    
    const user = await userModel.findOne({email});
    if(!user){
      return res.json({success: false, message: 'User not found'})
    }

    if (user.resetOtp === "" || user.resetOtp !== otp) {
      return res.json({success: false, message: 'Invalid OTP'})
    }

    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({success: false, message: 'OTP Expired!'})
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    user.resetOtp = '';
    user.resetOtpExpireAt = 0;

    await user.save();

    return res.json({success: true, message: 'Password has been reset successfully'})
    
  } catch (error) {
    return res.json({success: false, message: error.message})
  }
}