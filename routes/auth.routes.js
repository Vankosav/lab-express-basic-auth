const express = require("express");
const router = express.Router();

// ℹ️ Handles password encryption
const bcryptjs = require("bcryptjs");
const mongoose = require("mongoose");

// How many rounds should bcrypt run the salt (default - 10 rounds)
const saltRounds = 10;

// Require the User model in order to interact with the database
const User = require("../models/User.model");

// GET /auth/signup
router.get("/signup", (req, res) => {
    res.render("auth/signup", { errorMessage: ""});
  });

  // POST /auth/signup
router.post("/signup",  (req, res) => {
    const { username, email, password } = req.body;
  
    // Check that username, email, and password are provided
    if (username === "" || password === "") {
      res.status(400).render("auth/signup", {
        errorMessage:
          "All fields are mandatory. Please provide your username, email and password.",
      });
  
      return;
    }
  
    if (password.length < 6) {
      res.status(400).render("auth/signup", {
        errorMessage: "Your password needs to be at least 6 characters long.",
      });
  
      return;
    }
});

 // Create a new user - start by hashing the password
 bcryptjs
 .genSalt(saltRounds)
 .then((salt) => bcryptjs.hash(password, salt))
 .then((passwordHash) => {
   // Create a user and save it in the database
   return User.create({ username, password: passwordHash });
 })
 .then((user) => {
   res.redirect("/auth/login");
 })
 .catch((error) => {
   if (error instanceof mongoose.Error.ValidationError) {
     res.status(500).render("auth/signup", { errorMessage: error.message });
   } else if (error.code === 11000) {
     res.status(500).render("auth/signup", {
       errorMessage:
         "Username and email need to be unique. Provide a valid username or email.",
     });
    }
});


module.exports = router;