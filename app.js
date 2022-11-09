require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const { urlencoded } = require('body-parser');
const morgan  = require('morgan');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocal = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2');
const findOrCreate = require('mongoose-findorcreate');


// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRound = 10;
var schema = mongoose.Schema;


mongoose.connect('mongodb://localhost:27017/userDB');

const userSchema = schema({
    email: String,
    password: String,
    googleId: String,
    googleName: String,
    googlePhoto: String,
    githubId: String,
    gitubUsername: String,
    secret: String  
});

userSchema.plugin(passportLocal);
userSchema.plugin(findOrCreate);


// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"]  });
const User = new mongoose.model('user', userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, picture: user.picture});
    });
});
  
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

///// l'authentifiaction en passant par google  //////////
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    scope: 'profile'
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({googleId: profile.id},
        {googleName: profile.displayName},
        {googlePhoto: profile['_json'].picture}, (err,user)=>{
        return cb (err,user);
    })
  }
));

///// l'authentifiaction en passant par github //////////
passport.use(new GitHubStrategy({
    clientID: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets"
  },
  function(accessToken, refreshToken, profile, done) {
    User.findOrCreate(
        { githubId: profile.id },
        {gitubUsername: profile.username},
        {githubPhoto: profile['_json'].avatar_url},(err, user)=> {
      return done(err, user);
    });
  }
));

const db = mongoose.connection;
db.once('open',(err)=>{
    if(!err){
        console.log('connection a la base de donnee ok !!');
    }else{
        console.log(err);
    }
});

const app = express();
const port = 3000;
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(morgan('dev'));
app.use(session({
    secret: "Notre petit secret",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());
 

app.get('/', (req, res) =>{
    res.render("home");
});

app.get('/login', (req, res) =>{
    res.render("login");
});

app.get("/submit", (req,res)=>{
    if(req.isAuthenticated()){
        res.render('submit');
    }else{
        res.redirect('login');
    }
});

app.post("/submit",(req,res)=>{
    const submittedSecret = req.body.secret;
    User.findById(req.user.id, (err,foundUser)=>{
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = submittedSecret;
                foundUser.save(()=>{
                    res.redirect('secrets')
                });
            }
        }
    });

});

app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }
));

app.get('/auth/github/secrets', 
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });


app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] })
);

app.get('/auth/google/secrets', 
  passport.authenticate("google", { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
});

app.get('/logout',(req,res)=>{
        req.logout(function(err) {
            if (err) { 
            console.log(err);;
            }
        res.redirect('/');
    })
});

app.get('/register', (req, res) =>{
    res.render("register");
});

app.get('/secrets', (req,res)=>{
    if(req.isAuthenticated()){
        User.find({"secret": {$ne: null}}, (err, foundUser)=>{
            if(err){
                console.log(err);
            }else{
                res.render("secrets", {usersWithSecrets: foundUser})
            }
        });    
    }else{
        res.redirect('/login');
    }
    
});


app.post('/register',(req,res)=>{
    
    // bcrypt.hash(req.body.password, saltRound,(err, hash)=>{

    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
            
    //     })
    //     newUser.save((err)=>{
    //         if(!err){
    //             res.render('secrets')
    //         }else{
    //             res.render('error')
    //         }
    //     });
    // })

    // An ather way to registre ///
    User.register({username: req.body.username}, req.body.password,(err,user)=>{
        if(err){
            console.log(err);
            res.render('register');
        }else{
            passport.authenticate("local")(req,res, function(){
                res.render('home');
            });
        }
    });
    
});

app.post('/login',(req, res)=>{
    // const username = req.body.username;
    // const pwd = req.body.password;

    // User.findOne({email: username},(err,foundUser)=>{
    //     if(err){
    //         res.render("error");
    //     }else{
    //         if(foundUser){
    //             bcrypt.compare(pwd, foundUser.password,(err,result)=>{
    //                if(result == true){
    //                 res.render('secrets');
    //                }else{
    //                 res.render('error');
    //                }
    //             })
    //         }
    //     }
    // })
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req,res, function(){
                res.render("secrets");
            })
        }
    });


});

app.listen(port, () => console.log(`app listening on port ${port}!`)) 