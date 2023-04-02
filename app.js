require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config JSON response
app.use(express.json());

// Models
const User = require("./models/User");

// Open Route - Public Route
app.get("/", (req, res) => {
    res.status(200).json({ msg: "Welcome to the API!" });
});

// Private route
app.get("/user/:id", checkToken, async (req, res) => {
    const id = req.params.id;

    //check if user exists
    const user = await User.findById(id, "-password");

    if(!user) {
        return res.status(404).json({ msg: "User not found!" });
    }

    res.status(200).json({ user });
});

function checkToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token) {
        return res.status(401).json({ msg: "Access denied!" });1
    }

    try {
        const secret = process.env.SECRET;
        
        jwt.verify(token, secret);
        next(); 
    } catch (error) {
        console.log("Error: ", error);
        res.status(400).json({ msg: "Invalid token!" });
    }
}

// Register User
app.post("/auth/register", async (req, res) => {
    const { username, email, password, confirmPassword } = req.body;

    // validations
    if(!username) {
        return res.status(422).json({ msg: "Please enter a username!" });
    }
    if(!email) {
        return res.status(422).json({ msg: "Please enter a email!" });
    }
    if(!password) {
        return res.status(422).json({ msg: "Please enter a password!" });
    }

    if(password !== confirmPassword) {
        return res.status(422).json({ msg: "Passwords do not match!" });
    }

    // check if user already exists
    const userExists = await User.findOne({ email: email });

    if(userExists) {
        return res.status(422).json({ msg: "Please enter with another email!" });
    }

    // create password
    const salt = await bcrypt.genSalt(12);
    const passwordHash = await bcrypt.hash(password, salt);

    // create user
    const user = new User({
        username,
        email,
        password: passwordHash
    });

    try {
        await user.save();
        res.status(201).json({ msg: "User created successfully!" });
    } catch (error) {
        console.log("Error:", error);
        res.status(500).json({ msg: "Something went wrong! Try again later." });
    }
});

/// Login User
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    if(!email) {
        return res.status(422).json({ msg: "Please enter a email!" });
    }

    if(!password) {
        return res.status(422).json({ msg: "Please enter a password!" });

    }
    
    // check if user already exists
    const user = await User.findOne({ email: email });

    if(!user) {
        return res.status(404).json({ msg: "User not found!" });
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password);

    if(!checkPassword) {
        return res.status(422).json({ msg: "Incorrect password!" });
    }

    try {
        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
                id: user._id
            },
            secret, 
        );
        res.status(200).json({ msg: "User logged in successfully!", token });
    } catch (error) {
        console.log("Error: ", error);
        res.status(500).json({ msg: "Something went wrong! Try again later." });
    }
});

// Credentials
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;

mongoose.connect(
        `mongodb+srv://${dbUser}:${dbPassword}@authcluster.akmn4ef.mongodb.net/AuthDatabase?retryWrites=true&w=majority`
    ).then(
        console.log("Connected to DataBase!"),
        app.listen(3000)
    ).catch((err) => console.log(err));