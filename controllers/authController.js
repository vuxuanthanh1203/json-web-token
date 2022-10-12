const bcrypt = require('bcrypt');
const User = require('../models/User');
const jwt = require("jsonwebtoken");


const register = async (req, res) => {
    try {
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(req.body.password, salt);

        // Create New User
        const newUser = await new User({
            username: req.body.username,
            email: req.body.email,
            password: hashPassword
        });

        // Save to database
        const user = await newUser.save();
        res.status(201).json({
            message: 'User created',
            data: user
        })
    } catch (error) {
        res.status(500).json({ error });
    }
}

const generateAccessToken = (user) => {
    return jwt.sign(
        {
            id: user._id,
            admin: user.admin
        },
        process.env.JWT_ACCESS_KEY,
        {
            expiresIn: "30s"
        }
    )
}
const generateRefreshToken = (user) => {
    return jwt.sign(
        {
            id: user._id,
            admin: user.admin
        },
        process.env.JWT_REFRESH_KEY,
        {
            expiresIn: "365d"
        }
    )
}

const login = async (req, res) => {
    try {

        const { username, password } = req.body

        const user = await User.findOne({ username: username }).select('+password');
        if (!user) {
            return res.status(404).json("Wrong username")
        }

        const validPassword = await bcrypt.compare(
            password,
            user.password
        )

        if (!validPassword) {
            return res.status(404).json("Wrong password");
        }

        if (user && validPassword) {
            const accessToken = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);
            res.cookie("refreshToken", refreshToken, {
                httpOnly: true,
                secure: false,
                path: "/",
                sameSite: "strict"
            })
            return res.status(200).json({
                data: user,
                accessToken: accessToken
            })
        }
    } catch (error) {
        return res.status(500).json({ error });
    }
}

const requestRefreshToken = (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (!refreshToken) {
        return res.status(401).json("You are not authenticated");
    }
    jwt.verify(refreshToken, process.env.JWT_REFRESH_KEY, (err, user) => {
        if (err) {
            console.log(err);
        }
        // Create new access token and refresh token
        const newAccessToken = generateAccessToken(user);
        const newRefreshToken = generateRefreshToken(user);
        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: false,
            path: "/",
            sameSite: "strict"
        })
        return res.status(200).json({
            data: user,
            accessToken: newAccessToken
        })
    })
}

const logout = (req, res) => {
    res.clearCookie("refreshToken");

    res.status(200).json("Logged out!");
}

module.exports = {
    register,
    login,
    requestRefreshToken,
    logout
}