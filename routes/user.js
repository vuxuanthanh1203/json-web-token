const express = require('express');
const verifyToken = require('../middlewares/verifyToken');
const authAdmin = require('../middlewares/authAdmin');
const { getAllUser, deleteUser } = require('../controllers/userController');


const router = express.Router();

// Get all user
router.get("/", verifyToken, getAllUser);

// Delete user
router.delete("/:id", authAdmin, deleteUser);


module.exports = router;