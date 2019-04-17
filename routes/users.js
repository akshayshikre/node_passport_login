const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport');
//user model
const User = require('../models/User');

//login page
router.get('/login',(req,res) => res.render('login'));

//login handel
router.post('/login',(req,res,next) => {
  passport.authenticate('local',{
    successRedirect: '/dashboard',
    failureRedirect: '/users/login',
    failureFlash: true 
  })(req,res,next);
});

//logout handel
router.get('/logout',(req,res) => {
req.logout();
req.flash('success_msg', 'You are logged out');
res.redirect('/users/login');
});

//register page
router.get('/register',(req,res) => res.render('register'));

//register handel
router.post('/register',(req,res) => {
  const { name, email, password, password2 } = req.body;
  let errors = [];
   //Check errors
   if(!name || !email || !password || !password2){
     errors.push({ msg: 'Please fill in all fields!'});
   }
   if(password !== password2){
    errors.push({ msg: 'Passwords do not match'});
   }
   if(password.length < 6){
    errors.push({ msg: 'Password length should be at least 6'});
   }

   //Send response
   if(errors.length>0){
    res.render('register',{ errors, name, email, password, password2});
   }else{
    //Validations are passed
    User.findOne({ email: email})
    .then( user => {
      if(user){
        errors.push({ msg: 'Email is already registered'});
        res.render('register',{ errors, name, email, password, password2});
      }else{
        const newUser = new User({
          name,
          email,
          password
        });
        //hash it
        bcrypt.genSalt(10,(err,salt) => 
        bcrypt.hash(newUser.password,salt,(err, hash) =>{
          if(err) throw err;
          //set hashed password
          newUser.password = hash;
          //save user
          newUser.save()
          .then(user => {
            req.flash('success_msg', 'You are now registered and can login');
            res.redirect('/users/login')})
          .catch(err => console.log(err));
        }));
        console.log(newUser);
      }
    })
    .catch(err => console.log(err));
   }
   
});

module.exports = router; 