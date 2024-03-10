const express = require("express");
const bodyParser = require("body-parser");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcrypt");

const cookieParser = require("cookie-parser");

const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
const path = require("path");

const prisma = new PrismaClient();

app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.engine("html", require("ejs").renderFile);
app.set("view engine", "html");
app.set("views", path.join(__dirname, "./views"));

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("login");
});
app.post("/login", async (req, res) => {
  try {
    const user = await prisma.users.findMany({
      where: { email: req.body.email },
    });
    const validation = bcrypt.compareSync(req.body.password, user[0].password);
    if (!validation) {
      // Senha incorreta
      res.redirect("/login");
    } else {
      const token = jwt.sign({ id: user[0].id }, process.env.SECRET);
      res.cookie("token", token).redirect("/account");
    }
  } catch (error) {
    throw new Error(error);
  }
});

app.get("/register", (req, res) => {
  res.render("register");
});
app.post("/register", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    await prisma.users.create({
      data: {
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword,
      },
    });
    res.redirect("/login");
  } catch (error) {
    throw new Error(error);
  }
});

const validationToken = (req, res, next) => {
  const tokenCookie = req.cookies["token"];

  if (!tokenCookie) {
    res.redirect("/login");
  }

  try {
    jwt.verify(tokenCookie, process.env.SECRET);
    next();
  } catch (error) {
    console.log(error);
    res.redirect("/login");
  }
};

app.get("/account", validationToken, (req, res) => {
  res.render("account");
});

app.listen(3000, () => {
  console.log("server running on port 3000!");
});
