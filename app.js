//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
	email: String,
	password: String,
});

//level 2 use mongoose-encryotion
//const secret = "Thisisourlittlesecret."; //Encryption Key
//userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

//level 3 use environment vairable to hide key
userSchema.plugin(encrypt, {secret:process.env.SECRET,encryptedFields:["password"]})


const User = new mongoose.model("User", userSchema);

app.get("/", function (req, res) {
	res.render("home");
});

app
	.route("/login")
	.get(function (req, res) {
		res.render("login");
	})
	.post(function (req, res) {
		User.findOne({ email: req.body.username }, function (err, foundUser) {
			if (err) {
				console.log(err);
			} else {
				if (foundUser) {
					if (foundUser.password === req.body.password) {
						res.render("secrets");
					} else {
					}
				}
			}
		});
	});

app
	.route("/register")
	.get(function (req, res) {
		res.render("register");
	})
	.post(function (req, res) {
		const newUser = new User({
			email: req.body.username,
			password: req.body.password,
		});
		newUser.save(function (err) {
			if (err) {
				console.log(err);
			} else {
				res.render("secrets");
			}
		});
	});

app.get("/secrets", function (req, res) {
	res.render("secrets");
});

app.get("/submit", function (req, res) {
	res.render("submit");
});

app.listen(3000, function () {
	console.log("Server started on port 3000");
});
