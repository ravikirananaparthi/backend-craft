import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import Jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

mongoose
  .connect("mongodb://localhost:27017", {
    dbName: "Backend",
  })
  .then(() => {
    console.log("DataBase Connected");
  })
  .catch((e) => {
    console.log(e);
  });

//creating schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
});

//creating model in Database collection
const User = mongoose.model("User", userSchema);

const app = express();

//body parsing midddle wares
app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// setting EJS engine
app.set("view engine", "ejs");

const isAuthenticated = async (req, res, next) => {
  const { token } = req.cookies;
  if (token) {
    const decoded = Jwt.verify(token, "abcdef");

    req.user = await User.findById(decoded._id);

    next();
  } else {
    res.redirect("/login");
  }
};

app.get("/", isAuthenticated, (req, res) => {
  res.render("logout", { name: req.user.name });
});

app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  let user = await User.findOne({ email });

  if (!user) {
    return res.redirect("/register");
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.render("login", { email, message: "Incorrect Password" });
  }

  const token = Jwt.sign({ _id: user._id }, "abcdef");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 6000),
  });

  res.redirect("/");
});
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;
  let user = await User.findOne({ email });

  if (user) {
    return res.redirect("/login");
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  user = await User.create({
    name,
    email,
    password,
  });
  const token = Jwt.sign({ _id: user._id }, "abcdef");

  res.cookie("token", token, {
    httpOnly: true,
    expires: new Date(Date.now() + 6000),
  });

  res.redirect("/");
});

app.get("/logout", (req, res) => {
  res.cookie("token", "null", {
    httpOnly: true,
    expires: new Date(Date.now()),
  });

  res.redirect("/");
});

app.listen(5000, () => {
  console.log("Server is running on port 5000");
});
