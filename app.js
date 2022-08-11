//jshint esversion:6
require("dotenv").config(); //level 3 hide encryption key
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");//level 2 convert plain text into code
const md5 = require("md5"); //level 4 haching
const bcrypt = require("bcrypt"); //level 5 salting
const saltRounds = 10; //level 5

//npm i passport passport-local passport-local-mongoose express-session
const session = require("express-session"); //level 6 cookies
const passport = require("passport"); //level 6 cookies
const passportLocalMongoose = require("passport-local-mongoose"); //level 6 cookies

//level 7 use openauth
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate")//third-party npm to make findOrCreate work which is a sudo code in passport


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

/////////Level 6 cookies
app.use(
	session({
		secret: "Our little secret.",
		resave: false,
		saveUninitialized: false,
	})
);
app.use(passport.initialize());
app.use(passport.session()); 
///////////////////////

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
    googleId:String,
    secret:String
});

//level 2 use mongoose-encryotion
//const secret = "Thisisourlittlesecret."; //Encryption Key
//userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

//level 3 use environment vairable to hide key
//userSchema.plugin(encrypt, {secret:process.env.SECRET,encryptedFields:["password"]})

//level 6 cokkies
userSchema.plugin(passportLocalMongoose);
//level 7 
userSchema.plugin(findOrCreate)

const User = new mongoose.model("User", userSchema);

///////level 6
// passport.use(User.createStrategy());
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
///////////////
//////level 7
passport.serializeUser(function(user,done){
    done(null,user.id)
})

passport.deserializeUser(function(id,done){
    User.findById(id, function(err,user){
        done(err,user)
    })
})

//////level 7
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
/////////

app.get("/", function (req, res) {
	res.render("home");
});

/////////level 7
app.get("/auth/google",
  passport.authenticate("google", { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
////////////
app
	.route("/login")
	.get(function (req, res) {
		res.render("login");
	})
	.post(function (req, res) {
		// User.findOne({ email: req.body.username }, function (err, foundUser) {
		// 	if (err) {
		// 		console.log(err);
		// 	} else {
		// 		if (foundUser) {
		// 			//if (foundUser.password === md5(req.body.password)) {//level 4
		//             bcrypt.compare(req.body.password, foundUser.password, function(err, result) {//level 5
		//                 if (result) {
		//                     res.render("secrets");
		//                 } else {
		//                 }
		//             });
		// 		}
		// 	}
		// });

        const user = new User({
            username:req.body.username,
            passport:req.body.password
        })
        req.login(user,function(err){
            if(err){
                console.log(err)
            } else {
                passport.authenticate("local")(req,res,function(){
                    res.redirect("/secrets")
                })
            }
        })
	});

app
	.route("/register")
	.get(function (req, res) {
		res.render("register");
	})
	.post(function (req, res) {
		// bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
		// 	//level 5
		// 	const newUser = new User({
		// 		email: req.body.username,
		// 		//password: md5(req.body.password),//level 4
		// 		password: hash,
		// 	});
		// 	newUser.save(function (err) {
		// 		if (err) {
		// 			console.log(err);
		// 		} else {
		// 			res.render("secrets");
		// 		}
		// 	});
		// });

        User.register({username:req.body.username}, req.body.password, function(err,user) {
            if(err) {
                console.log(err);
                res.redirect("/register")
            } else {
                passport.authenticate("local")(req,res,function(){
                    res.redirect("/secrets")
                })
            }
        })
	});

app.route("/secrets")
.get(function (req, res) {
	User.find({"secret":{$ne:null}}, function(err,foundUsers){
        if(!err){
            res.render("secrets",{usersWithSecrets:foundUsers})
        }
       
    })
});

app.route("/submit")
.get(function (req, res) {
    if (req.isAuthenticated()){
        res.render("submit")
    } else {
        res.redirect("/login")
    }
})
.post(function(req,res){
    const submittedSecret = req.body.secret
    User.findById(req.user.id,function(err,foundUser){
        if(err){
            console.log(err)
        } else {
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect("/secrets")
                })
            }
        }
    })
})

app.get("/logout", function(req,res){
    req.logout(function(err){
    });
    res.redirect("/")
})

app.listen(3000, function () {
	console.log("Server started on port 3000");
});
