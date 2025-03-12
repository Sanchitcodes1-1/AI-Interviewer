const jwt = require('jsonwebtoken');

//Middleware to authenticate and verify JWT token
const authenticateToken = (req,res,next) => {
    //Get the token from Authorization header
    const token = req.header('Authorization')?.replace('Bearer ', '');

    //If no token, return 401 Unauthorized error
    if(!token) {
        return res.status(401).json({ error: 'Access denied, no token provided'});
    }
    try {
        //Verify the token and decode the payload
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        //Attach user info(id,email) to the request object
        req.user = decoded; //You can now access user info in other routes using req.user

        next();
    } catch(error) {
        //If the token is invalid or expired ,return a 400 error
        return res.status(400).json({error: 'Invalid or expired token'});

}
};

module.exports = authenticateToken;