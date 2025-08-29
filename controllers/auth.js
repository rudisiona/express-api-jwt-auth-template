const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const User = require("../models/user");
const jwt = require("jsonwebtoken");

const saltRounds = 12;

router.post("/sign-up", async (req, res) => {
  try {
    // make sure a user with this username does not exist
    const userInDatabase = await User.findOne({ username: req.body.username });

    if (userInDatabase) {
      return res.status(409).json({ err: "Username already taken" });
    }

    // No user with that username, lets create a new user
    const user = await User.create({
      username: req.body.username,
      hashedPassword: bcrypt.hashSync(req.body.password, saltRounds),
    });

    const payload = { username: user.username, _id: user._id };

    // Create a new auth jwt token for the new user
    const token = jwt.sign({ payload }, process.env.JWT_SECRET);

    res.status(201).json({ token });
  } catch (error) {
    res.status(500).json({ err: error.message });
  }
});

router.post("/sign-in", async (req, res) => {
  try {
    // make sure a user with this username does not exist
    const userInDatabase = await User.findOne({ username: req.body.username });

    if (!userInDatabase) {
      return res.status(409).json({ err: "Invalid Credentials, user does not exist" });
    }

    // this will return true if the password match and false if they do not
    const isPasswordCorrect = bcrypt.compareSync(
      req.body.password,
      userInDatabase.hashedPassword
    );

    if (!isPasswordCorrect) {
      return res.status(401).json({ err: "Invalid Password" });
    }

    const payload = {
      username: userInDatabase.username,
      _id: userInDatabase._id,
    };

    // Create a new auth jwt token for the user
    const token = jwt.sign({ payload }, process.env.JWT_SECRET);

    res.status(200).json({ token });

  } catch (error) {
    res.status(500).json({ err: error.message });
  }
});

module.exports = router;