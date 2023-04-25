const express = require("express");
const router = express.Router();

// ℹ️ Handles password encryption
const bcryptjs = require("bcryptjs");
const mongoose = require("mongoose");

// How many rounds should bcrypt run the salt (default - 10 rounds)
const saltRounds = 10;

// Require the User model in order to interact with the database
const User = require("../models/User.model");

const isLoggedOut = require("../middleware/isLoggedOut");
//const isLoggedIn = require("../middleware/isLoggedIn");

// GET /auth/signup
router.get("/signup", isLoggedOut, (req, res) => {
    res.render("auth/signup", { errorMessage: ""});
  });

  // POST /auth/signup
router.post("/signup", isLoggedOut, (req, res) => {
    const { username, password } = req.body;
  
    // Check that username and password are provided
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
         "Username needs to be unique. Provide a valid username.",
     });
    }
});
});



 

router.get("/login", isLoggedOut, (req, res) => {
    res.render("auth/login");
  });

  router.post("/login", isLoggedOut, (req, res, next) => {
    const { username, password } = req.body;
  
    if (username === "" || password === "") {
        res.status(400).render("auth/login", {
          errorMessage:
            "All fields are mandatory. Please provide username and password.",
        });
    
        return;
      }
      if (password.length < 6) {
        return res.status(400).render("auth/login", {
          errorMessage: "Your password needs to be at least 6 characters long.",
        });
      }
    
      // Search the database for a user with the email submitted in the form
      User.findOne({ username })
        .then((user) => {
          console.log(user);
          // If the user isn't found, send an error message that user provided wrong credentials
          if (!user) {
            res
              .status(400)
              .render("auth/login", { errorMessage: "Wrong credentials." });
            return;
          }
    
          // If user is found based on the username, check if the in putted password matches the one saved in the database
          bcryptjs
            .compare(password, user.password)
            .then((isSamePassword) => {
              if (!isSamePassword) {
                res
                  .status(400)
                  .render("auth/login", { errorMessage: "Wrong credentials." });
                return;
              } else {
                req.session.currentUser = user.toObject();
          // Remove the password field
          delete req.session.currentUser.password;

          res.redirect("/auth/userProfile")
              }
        })
        .catch((err) => next(err)); // In this case, we send error handling to the error handling middleware.
    })
    .catch((err) => next(err));
});
           
router.get("/userProfile", isLoggedOut, (req, res) => {
  res.render("auth/user-profile");
});

        

module.exports = router;