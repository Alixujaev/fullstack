const { Router } = require("express");
const bcrypt = require("bcryptjs");
const {body, validationResult} = require("express-validator/check")
const User = require("../models/user");
const { registerValidators } = require("../utils/validators");
const router = Router();

router.get("/login", async (req, res) => {
  res.render("auth/login", {
    title: "Register",
    isLogin: true,
    registerError: req.flash("registerError"),
    loginError: req.flash("loginError"),
  });
});

router.get("/logout", async (req, res) => {
  req.session.destroy(() => {
    res.redirect("/auth/login#login");
  });
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const newEmail = email.toLowerCase()
    const candidate = await User.findOne({ newEmail });

    if (candidate) {
      console.log(candidate);
      const samePas = bcrypt.compareSync(password, candidate.password);
      // const samePas = password === candidate.password;
      console.log(samePas);
      if (!samePas) {
        req.flash("loginError", "Password wrong");
        res.redirect("/auth/login#login");
      }else{
        req.session.user = candidate;
        req.session.isAuthenticated = true;
        req.session.save((err) => {
          if (err) throw err;

          res.redirect("/");
        });
      }
    } else {
      req.flash("loginError", "Password wrong");
      res.redirect("/auth/login#login");
    }
  } catch (e) {
    req.flash("loginError", "This username does not found");
    console.log(e);
  }
});

router.post("/register", registerValidators, async (req, res) => {
  try {
    const { email, password, name, confirm } = req.body;

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      req.flash("registerError", errors.array()[0].msg);
      return res.status(422).redirect("/auth/login#register");
    }

    const hashPass = await bcrypt.hashSync(password, 10);
    const user = new User({
      email: email,
      name: name,
      password: hashPass,
      cart: { items: [] },
    });
    await user.save();
    res.redirect("/auth/login#login"); 
  } catch (e) {
    console.log(e);
  }
});

module.exports = router;
