const express = require('express');
const verifyToken = require('../middlewares/verifyToken');

const { register, login, requestRefreshToken, logout } = require('../controllers/authController');

const router = express.Router();

router.post("/register", register);
router.post("/login", login);

// Refresh
router.post("/refresh", requestRefreshToken);

// Logout
router.post("/logout", verifyToken, logout);

module.exports = router;