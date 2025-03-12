const authorizeRole = (role) => {
    return (req,res,next) => {
        //Check if the user has the required role
        if(req.user.role !== role) {
            return res.status(403).json({ error: 'Access denied, insufficient permissions' });
        }
        next(); //If the user has the required role, continue to the route handler
    };
};

module.exports = authorizeRole;