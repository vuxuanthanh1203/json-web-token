const verifyToken = require("./verifyToken");

const authAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        if (req.user.id == req.params.id || req.user.admin) {
            next();
        } else {
            res.status(403).json({
                message: "You cannot perform this action"
            })
        }

    })
}

module.exports = authAdmin;