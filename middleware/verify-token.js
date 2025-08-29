const jwt = require('jsonwebtoken')

function verifyToken (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1]; // ['Bearer', '<token>'][1]

    // if the token is valid and was signed with out secret key
    // this will return whatever was in the payload when this token
    // was create
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded.payload // contains the user data that was stored on sign-in
    
    next() // pass the the request to the next function or route
  } catch (error) {
    res.status(401).json({ err: "Invalid Token" });
  }
}

module.exports = verifyToken