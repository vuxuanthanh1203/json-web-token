const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const token = req.headers.token;
    if (token) {
        const accessToken = token.split(" ")[1];
        jwt.verify(accessToken, process.env.JWT_ACCESS_KEY, (err, user) => {
            if (err) {
                return res.status(403).json({
                    message: "Token is not valid"
                })
            }
            req.user = user;
            next();
        })
    } else {
        return res.status(401).json({
            message: "You cannot perform this action"
        })
    }
}

module.exports = verifyToken;