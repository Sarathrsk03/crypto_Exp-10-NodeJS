// index.js

const express = require("express");
const fs = require("fs");
const path = require("path");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcryptjs = require("bcryptjs");

const app = express();

// Middleware setup
app.use(express.json()); // Parse JSON requests
app.use(cookieParser()); // Parse cookies
app.use(express.urlencoded({ extended: false })); // Parse URL-encoded data

// Set up paths for templates and public files
const templatePath = path.join(__dirname, "../templates");
const publicPath = path.join(__dirname, "../public");

// Path for userDetails.csv
const csvFilePath = path.join(__dirname, "userDetails.csv");

// Configure the app
app.set("view engine", "hbs"); // Set the view engine to Handlebars
app.set("views", templatePath); // Set the views directory
app.use(express.static(publicPath)); // Serve static files from the public directory

// Helper functions
async function hashPass(password) {
  return await bcryptjs.hash(password, 10);
}

async function compare(userPass, hashPass) {
  return await bcryptjs.compare(userPass, hashPass);
}

// Function to write user details to CSV file
function writeToCSV(data) {
  const headers = Object.keys(data[0]).join(",");
  const values = data.map((user) => Object.values(user).join(","));
  const content = `${headers}\n${values.join("\n")}`;

  fs.writeFileSync(csvFilePath, content);
}

// Function to read user details from CSV file
function readFromCSV() {
  try {
    const fileContent = fs.readFileSync(csvFilePath, "utf-8");
    return fileContent
      .split("\n")
      .map((line) => {
        const values = line.split(",");
        return {
          name: values[0],
          password: values[1],
          token: values[2],
        };
      })
      .filter((user) => user.name && user.password && user.token);
  } catch (error) {
    return [];
  }
}

// Route for the home page
app.get("/", (req, res) => {
  if (req.cookies.jwt) {
    try {
      const verify = jwt.verify(req.cookies.jwt, "yourSecretKey");
      res.render("home", { name: verify.name });
    } catch (error) {
      res.render("login");
    }
  } else {
    res.render("login");
  }
});

// Route for the signup page
app.get("/signup", (req, res) => {
  res.render("signup");
});

// Handle signup form submission
app.post("/signup", async (req, res) => {
  try {
    const token = jwt.sign({ name: req.body.name }, "yourSecretKey");
    const hashedPassword = await hashPass(req.body.password);

    const userData = {
      name: req.body.name,
      password: hashedPassword,
      token: token,
    };

    // Read existing user data
    const existingUserData = readFromCSV();

    // Add new user data
    writeToCSV([...existingUserData, userData]);

    res.redirect("/login");
  } catch (error) {
    res.send("Error during signup");
  }
});

// Route for the login page
app.get("/login", (req, res) => {
  res.render("login");
});

// Handle login form submission
app.post("/login", async (req, res) => {
  try {
    const userData = readFromCSV();

    const user = userData.find((u) => u.name === req.body.name);

    if (user && (await compare(req.body.password, user.password))) {
      res.cookie("jwt", user.token, {
        maxAge: 600000,
        httpOnly: true,
      });
      res.render("home", { name: req.body.name });
    } else {
      res.send("Wrong username or password");
    }
  } catch (error) {
    res.send("Error during login");
  }
});

// Route for logout
app.post("/logout", (req, res) => {
  res.clearCookie("jwt");
  res.redirect("/login");
});

// Start the server on port 3000
app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
