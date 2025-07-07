import jwt from 'jsonwebtoken'

const userAuth = async (req, res, next) => {
  const {token} = req.cookies;

  if (!token) {
    return res.json({success: false, message: 'Not Authorized, Login Again'})
  }

  try {
    const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

    if (tokenDecode.id) {
      req.userId = tokenDecode.id;  // ✅ set it here, not in req.body
    } else{
      return res.json({success: false, message: 'Not Authorized, Login Again'})
    }

    next();

   /* 
   
    try {
      const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);
      req.userId = tokenDecode.id;
      next();
    } 

   */
    
  } catch (error) {
    res.json({success: false, message: error.message})
  }
}

export default userAuth;