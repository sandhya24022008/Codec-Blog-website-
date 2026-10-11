
require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const crypto = require("crypto");
const slugify = require("slugify");
const { body, validationResult } = require("express-validator");
const mongoSanitize = require("express-mongo-sanitize");
const methodOverride = require("method-override");

const app = express();

app.set("view engine", "ejs");
app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: "20kb" }));
app.use(express.json({ limit: "20kb" }));
app.use(methodOverride("_method"));
app.use(mongoSanitize());

const User = mongoose.model("User", new mongoose.Schema({
  username: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" }
}, { timestamps: true }));

const Blog = mongoose.model("Blog", new mongoose.Schema({
  title: { type: String, required: true, trim: true, maxlength: 120 },
  slug: { type: String, required: true, unique: true },
  content: { type: String, required: true, maxlength: 20000 },
  author: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }
}, { timestamps: true }));

app.use(session({
  name: "blog.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URI
  }),
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 2
  }
}));

// CSRF protection for browser forms and state-changing requests
app.use((req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
  }

  res.locals.csrfToken = req.session.csrfToken;
  res.locals.currentUser = req.session.user || null;

  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    const token = req.body?._csrf || req.get("x-csrf-token") || "";
    const expected = req.session.csrfToken;

    if (
      typeof token !== "string" ||
      token.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected))
    ) {
      return res.status(403).send("Invalid security token. Refresh and try again.");
    }
  }

  next();
});

app.use((req, res, next) => {
  res.locals.message = req.session.message || "";
  delete req.session.message;
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).send("Admin access required.");
  }
  next();
}

function validInput(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    req.session.message = errors.array()[0].msg;
    return res.redirect("back");
  }
  next();
}

function makeSlug(title) {
  return slugify(title, {
    lower: true,
    strict: true,
    trim: true
  }).slice(0, 100) || "blog-post";
}

function canEdit(blog, user) {
  return user.role === "admin" ||
    blog.author.toString() === user.id;
}

app.get("/", async (req, res, next) => {
  try {
    const blogs = await Blog.find()
      .populate("author", "username")
      .sort({ createdAt: -1 });
    res.render("index", { blogs, page: "home", selectedBlog: null });
  } catch (err) {
    next(err);
  }
});

app.get("/register", (req, res) => {
  res.render("index", { page: "register", blogs: [], selectedBlog: null });
});

app.post("/register",
  body("username").trim().isLength({ min: 2, max: 40 })
    .withMessage("Username must be 2–40 characters."),
  body("email").trim().isEmail().normalizeEmail()
    .withMessage("Enter a valid email."),
  body("password").isLength({ min: 8, max: 100 })
    .withMessage("Password must be at least 8 characters."),
  validInput,
  async (req, res, next) => {
    try {
      const email = req.body.email.toLowerCase();
      if (await User.exists({ email })) {
        req.session.message = "Email is already registered.";
        return res.redirect("/register");
      }

      const user = await User.create({
        username: req.body.username,
        email,
        password: await bcrypt.hash(req.body.password, 12),
        role: "user"
      });

      req.session.regenerate(err => {
        if (err) return next(err);
        req.session.user = {
          id: user.id,
          username: user.username,
          role: user.role
        };
        req.session.message = "Account created successfully.";
        res.redirect("/");
      });
    } catch (err) {
      next(err);
    }
  }
);

app.get("/login", (req, res) => {
  res.render("index", { page: "login", blogs: [], selectedBlog: null });
});

app.post("/login", async (req, res, next) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    const user = await User.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.password))) {
      req.session.message = "Invalid email or password.";
      return res.redirect("/login");
    }

    req.session.regenerate(err => {
      if (err) return next(err);
      req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
      };
      req.session.message = "Logged in successfully.";
      res.redirect("/");
    });
  } catch (err) {
    next(err);
  }
});

app.post("/logout", requireLogin, (req, res, next) => {
  req.session.destroy(err => {
    if (err) return next(err);
    res.clearCookie("blog.sid");
    res.redirect("/");
  });
});

app.get("/new", requireLogin, (req, res) => {
  res.render("index", { page: "new", blogs: [], selectedBlog: null });
});

app.post("/blogs",
  requireLogin,
  body("title").trim().isLength({ min: 3, max: 120 })
    .withMessage("Title must be 3–120 characters."),
  body("content").trim().isLength({ min: 10, max: 20000 })
    .withMessage("Content must be 10–20,000 characters."),
  validInput,
  async (req, res, next) => {
    try {
      const base = makeSlug(req.body.title);
      const slug = `${base}-${crypto.randomBytes(3).toString("hex")}`;

      await Blog.create({
        title: req.body.title,
        slug,
        content: req.body.content,
        author: req.session.user.id
      });

      req.session.message = "Blog published!";
      res.redirect("/");
    } catch (err) {
      next(err);
    }
  }
);

app.get("/blogs/:slug", async (req, res, next) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug })
      .populate("author", "username");

    if (!blog) return res.status(404).send("Blog not found.");

    res.render("index", {
      page: "detail",
      blogs: [],
      selectedBlog: blog
    });
  } catch (err) {
    next(err);
  }
});

app.get("/blogs/:slug/edit", requireLogin, async (req, res, next) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug });
    if (!blog) return res.status(404).send("Blog not found.");
    if (!canEdit(blog, req.session.user)) {
      return res.status(403).send("You cannot edit this blog.");
    }

    res.render("index", {
      page: "edit",
      blogs: [],
      selectedBlog: blog
    });
  } catch (err) {
    next(err);
  }
});

app.put("/blogs/:slug",
  requireLogin,
  body("title").trim().isLength({ min: 3, max: 120 })
    .withMessage("Title must be 3–120 characters."),
  body("content").trim().isLength({ min: 10, max: 20000 })
    .withMessage("Content must be 10–20,000 characters."),
  validInput,
  async (req, res, next) => {
    try {
      const blog = await Blog.findOne({ slug: req.params.slug });
      if (!blog) return res.status(404).send("Blog not found.");
      if (!canEdit(blog, req.session.user)) {
        return res.status(403).send("You cannot edit this blog.");
      }

      blog.title = req.body.title;
      blog.content = req.body.content;
      await blog.save();

      req.session.message = "Blog updated!";
      res.redirect(`/blogs/${blog.slug}`);
    } catch (err) {
      next(err);
    }
  }
);

app.delete("/blogs/:slug", requireLogin, async (req, res, next) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug });
    if (!blog) return res.status(404).send("Blog not found.");
    if (!canEdit(blog, req.session.user)) {
      return res.status(403).send("You cannot delete this blog.");
    }

    await blog.deleteOne();
    req.session.message = "Blog deleted.";
    res.redirect("/");
  } catch (err) {
    next(err);
  }
});

// REST API: GET blog list and individual blog
app.get("/api/blogs", async (req, res, next) => {
  try {
    const blogs = await Blog.find().populate("author", "username")
      .sort({ createdAt: -1 });
    res.json(blogs);
  } catch (err) {
    next(err);
  }
});

app.get("/api/blogs/:slug", async (req, res, next) => {
  try {
    const blog = await Blog.findOne({ slug: req.params.slug })
      .populate("author", "username");
    if (!blog) return res.status(404).json({ error: "Blog not found." });
    res.json(blog);
  } catch (err) {
    next(err);
  }
});

// Create the initial admin from environment variables
async function createAdmin() {
  if (!process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD) {
    console.log("Admin setup skipped: set ADMIN_EMAIL and ADMIN_PASSWORD.");
    return;
  }

  const email = process.env.ADMIN_EMAIL.toLowerCase();
  let admin = await User.findOne({ email });

  if (!admin) {
    admin = await User.create({
      username: "Admin",
      email,
      password: await bcrypt.hash(process.env.ADMIN_PASSWORD, 12),
      role: "admin"
    });
    console.log("Initial admin account created.");
  } else if (admin.role !== "admin") {
    admin.role = "admin";
    await admin.save();
  }
}

app.use((err, req, res, next) => {
  console.error(err.message);
  if (res.headersSent) return next(err);
  res.status(500).send("Something went wrong. Check server configuration.");
});

const PORT = process.env.PORT || 3000;

if (!process.env.MONGODB_URI || !process.env.SESSION_SECRET) {
  console.error("Set MONGODB_URI and SESSION_SECRET in your environment.");
  process.exit(1);
}

mongoose.connect(process.env.MONGODB_URI)
  .then(createAdmin)
  .then(() => {
    app.listen(PORT, () => console.log(`Blog running on port ${PORT}`));
  })
  .catch(err => {
    console.error("Startup failed:", err.message);
    process.exit(1);
  });
