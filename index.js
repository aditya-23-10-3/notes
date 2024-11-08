import bodyParser from "body-parser";
import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import session from "express-session";
import flash from "connect-flash";

const app = express();
const port = 3000;
const saltRounds = 10;


// Set EJS as the view engine
app.set('view engine', 'ejs');

// Define the views directory (optional if located in 'views' folder)
app.set('views', './views');


// Configure session middleware
app.use(
  session({
    secret: "TOPSECRET",
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize connect-flash
app.use(flash());

// Make flash messages accessible in all views
app.use((req, res, next) => {
  res.locals.errorMessage = req.flash("errorMessage");
  next();
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());

// Database configuration
const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "notes_app",
  password: "new_password",
  port: 5432,
});
db.connect();

// Routes
app.get("/", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// Registration route
app.post("/register", async (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  try {
    const check = await db.query("SELECT * FROM users WHERE username = $1", [username]);
    if (check.rows.length > 0) {
      return res.redirect("/login");
    } else {
      const hash = await bcrypt.hash(password, saltRounds);
      const result = await db.query(
        "INSERT INTO users(username, password) VALUES ($1, $2) RETURNING *",
        [username, hash]
      );
      const user = result.rows[0];
      req.login(user, (err) => {
        if (err) return res.send("Error logging in after registration.");
        res.redirect("/notes");
      });
    }
  } catch (err) {
    console.log("Error during registration:", err);
    res.send("Registration error.");
  }
});

// Login route using passport
app.post(
  "/login",
  (req, res, next) => {
    passport.authenticate("local", (err, user, info) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        req.flash("errorMessage", "Wrong username or password");
        return res.redirect("/");
      }
      req.logIn(user, (err) => {
        if (err) {
          return next(err);
        }
        return res.redirect("/notes");
      });
    })(req, res, next);
  }
);


// Notes route with authentication check
app.get("/notes", async (req, res) => {

  if (!req.isAuthenticated()) {
    return res.redirect("/");
  }
  const userId = req.user.user_id;
  const result = await db.query(
    "SELECT * FROM notes WHERE user_id = $1 ORDER BY id", [userId]
  );
  const usersResult = await db.query("SELECT username FROM users");

  // Pass notes and usernames to the view
  res.render("main.ejs", { notes: result.rows, users: usersResult.rows });
});

// Add note route
app.post("/add", async (req, res) => {
  const title = req.body.title;
  const content = req.body.content;
  const isPrivate = req.body.is_private || false;
  const userId = req.user.user_id;

  try {
    
    await db.query(
      "INSERT INTO notes(title, content, is_private, user_id) VALUES($1, $2, $3, $4)",
      [title, content, isPrivate, userId]
    );
    res.redirect("/notes");
  } catch (err) {
    console.log("Error adding note:", err);
    res.send("Error adding note.");
  }
});

// Edit note route
app.post("/edit", async (req, res) => {
  const id = req.body.updateNoteId;
  const updatedTitle = req.body.updatedItemTitle;
  const updatedContent = req.body.updatedItemContent;

  try {
    await db.query("UPDATE notes SET title = $1, content = $2 WHERE id = $3", [
      updatedTitle,
      updatedContent,
      id,
    ]);
    res.redirect("/notes");
  } catch (err) {
    console.log("Error editing note:", err);
    res.send("Error editing note.");
  }
});

// Delete note route
app.post("/delete", async (req, res) => {
  const id = req.body.noteToBeDeleted;

  try {
    await db.query("DELETE FROM notes WHERE id = $1", [id]);
    res.redirect("/notes");
  } catch (err) {
    console.log("Error deleting note:", err);
    res.send("Error deleting note.");
  }
});

app.get('/user-notes', async (req, res) => {
  // if (!req.isAuthenticated()) {
  //   return res.redirect("/");
  // }
  const username = req.query.username;
  try {
      // Fetch notes for the selected user based on the username
      const notes = await db.query(
        'SELECT * FROM notes WHERE user_id = (SELECT user_id FROM users WHERE username = $1) AND is_private = false',
        [username]
    );
    console.log(notes.rows);

      res.render('userNotes', { username, notes: notes.rows });
  } catch (error) {
      console.log(error);
      res.status(500).send('Error fetching user notes');
  }
});


// Passport authentication strategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (isValidPassword) {
          return done(null, user);
        } else {
          return done(null, false, { message: "Incorrect password." });
        }
      } else {
        return done(null, false, { message: "User not found." });
      }
    } catch (err) {
      console.log("Error in authentication:", err);
      return done(err);
    }
  })
);

// Serialize user for session management
passport.serializeUser((user, cb) => {
  cb(null, user.user_id);
});

// Deserialize user to fetch data
passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE user_id = $1", [id]);
    cb(null, result.rows[0]);
  } catch (err) {
    console.log("Error deserializing user:", err);
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
