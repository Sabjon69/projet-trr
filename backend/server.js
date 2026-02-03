const express = require("express");
const fs = require("fs");
const bcrypt = require("bcrypt");
const session = require("express-session");
const bodyParser = require("body-parser");
const path = require("path");

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("../")); // pour servir tes fichiers HTML

app.use(
  session({
    secret: "secret-key-123",
    resave: false,
    saveUninitialized: false,
  })
);

// Charger les utilisateurs
function loadUsers() {
  return JSON.parse(fs.readFileSync("users.json"));
}

// Sauvegarder les utilisateurs
function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

// ---------------------------------------------
// 🔹 ROUTE : Création de compte
// ---------------------------------------------
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const users = loadUsers();

  // Vérifier si email existe déjà
  if (users.find((u) => u.email === email)) {
    return res.send("Email déjà utilisé");
  }

  // Hash du mot de passe
  const hashed = await bcrypt.hash(password, 10);

  users.push({ email, password: hashed });
  saveUsers(users);

  res.send("Compte créé avec succès !");
});

// ---------------------------------------------
// 🔹 ROUTE : Connexion
// ---------------------------------------------
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const users = loadUsers();
  const user = users.find((u) => u.email === email);

  if (!user) {
    return res.send("Utilisateur introuvable");
  }

  const match = await bcrypt.compare(password, user.password);

  if (!match) {
    return res.send("Mot de passe incorrect");
  }

  // Création de la session
  req.session.user = email;

  // Redirection vers c.html
  res.redirect("/connecter/c.html");
});

// ---------------------------------------------
// 🔹 ROUTE : Page protégée
// ---------------------------------------------
app.get("/connecter/c.html", (req, res, next) => {
  if (!req.session.user) {
    return res.redirect("/connecter/login.html");
  }
  next();
});

// ---------------------------------------------
// 🔹 Déconnexion
// ---------------------------------------------
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/connecter/login.html");
  });
});

// ---------------------------------------------
app.listen(PORT, () => {
  console.log("Serveur lancé sur http://localhost:" + PORT);
});
