const express = require("express");
const app = express();

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const userModel = require("./models/user");

const cookieParser = require("cookie-parser");
const path = require("path");
const { AsyncResource } = require("async_hooks");

app.set("view engine", "ejs");

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, "public")));
app.use(cookieParser());

app.get("/", (req, res) => {
  res.render("index");
});
app.post("/create", (req, res) => {
  let { name, email, password } = req.body;
  bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(password, salt, async (err, hash) => {
      let createdUser = await userModel.create({
        name,
        email,
        password: hash,
      });
      let token = jwt.sign({ email }, "secret");
      res.cookie("token", token);
      res.render("login");
    });
  });
});

app.get("/logout", (req, res) => {
  res.cookie("token", "");
  res.redirect("/");
});
app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", async (req, res) => {
  let readuser = await userModel.findOne({ email: req.body.email });
  if (!readuser) {
    return res.send("something went wrong");
  }
  bcrypt.compare(req.body.password, readuser.password, (err, result) => {
    
    if (result) {
      let token = jwt.sign({ email: readuser.email }, "secret");
      res.cookie("token", token);
      res.send("you can login");
     
    } else {
      res.send("something went wrong");
    }
  });
});

app.listen(3000);
