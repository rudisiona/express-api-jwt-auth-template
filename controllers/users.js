const express = require('express')
const router = express.Router()
const User = require('../models/user')
const verifyToken = require('../middleware/verify-token')

// Here we are protecting a route ensuring a user must be logged in
// to access any data
router.get('/', verifyToken, async (req, res) => {
    try {
        const users = await User.find({}, 'username')

        res.json(users)
        
    } catch (error) {
        res.status(500).json({err: error.message})
    }
})

// Here a user must be logged in and they can only access
// there own data
router.get('/:userId', verifyToken, async (req, res) => {
    try {
        console.log(req.user)
        // User id thats logged in has to match the userId in the request
        if(req.user._id !== req.params.userId){
            return res.status(403).json({err: 'Unauthorized'})
        }

        const user = await User.findById(req.params.userId)

        if(!user){
            return res.status(404).json({err: 'User not found'})
        }

        res.json({user})
        
    } catch (error) {
        res.status(500).json({err: error.message})
    }
})

module.exports = router