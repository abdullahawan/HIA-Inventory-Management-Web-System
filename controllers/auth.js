const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { validationResult } = require('express-validator/check');

const User = require('../models/users');

const AWS = require('aws-sdk');
AWS.config.update({region:'us-east-1'});

const docClient = new AWS.DynamoDB.DocumentClient();

exports.getLogin = (req, res) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message,
    oldInput: {
      email: "",
      password: ""
    },
    validationErrors: []
  });
};

exports.getSignup = (req, res) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'signup',
    errorMessage: message,
    oldInput: {
      email: "",
      password: "",
      confirmPassword: ""
    },
    validationErrors: []
  });
};

exports.postLogin = (req, res) => {
  let email = req.body.email;
  let password = req.body.password;

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password
      },
      validationErrors: errors.array()
    });
  }

  User.findById(email)
    .then(user => {
      if (Object.entries(user).length === 0 && user.constructor === Object) {
        return res.status(422).render('auth/login', {
          path: '/login',
          pageTitle: 'login',
          errorMessage: 'Invalid email or password',
          oldInput: {
            email: email,
            password: password
          },
          validationErrors: []
        });
      } else {
        bcrypt.compare(password, user.Item.password)
        .then(doMatch => {
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user.Item;
            return req.session.save((err) => {
              if (err) console.log(err);
              else return res.redirect('/');
            });
          } else {
            return res.status(422).render('auth/login', {
              path: '/login',
              pageTitle: 'login',
              errorMessage: 'Invalid email or password',
              oldInput: {
                email: email,
                password: password
              },
              validationErrors: []
            });
          }
        })
        .catch((err) => {
          console.log(err);
          res.redirect('/login');
        });
      }
    })
    .catch(err => {
      console.log(err);
      res.redirect('/login');
    })
};

exports.postSignup = (req, res) => {
  let email = req.body.email;
  let password = req.body.password;
  let storeLocation = req.body.storeLocation;

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'signup',
      errorMessage: errors.array()[0].msg,
      oldInput: {
        email: email,
        password: password,
        confirmPassword: req.body.confirmPassword
      },
      validationErrors: errors.array()
    });
  }

  bcrypt
  .hash(password, 12)
  .then(hashedPassword => {
    const user = new User(null, email, hashedPassword, null, null, storeLocation);
    return user.save();
  });
  res.redirect('/login');

}

exports.postLogout = (req, res) => {
  req.session.destroy((err) => {
    if (err) console.log(err);
    else res.redirect('/');
  });
};

exports.getReset = (req, res) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }

  res.render('auth/reset', {
    path:'/reset',
    pageTitle: 'Reset Password',
    errorMessage: message
  });
}

exports.postReset = (req, res) => {
  crypto.randomBytes(32, (err, buffer) => {
    if (err) {
      console.log(err);
      return res.redirect('/reset');
    }

    const token = buffer.toString('hex');
    User.findById(req.body.email)
      .then(user => {
        if (Object.entries(userDoc).length === 0) {
          req.flash('error', 'No user found');
          return res.redirect('/reset');
        } else {
          user.resetToken = token;
          user.resetTokenExpiration = Date.now() * 3600000;
          return user.save();
        }
      })
      .then(result => {
        console.log(result);
        //send email to user here
      })
      .catch(err => console.log(err));
  });
}

exports.getNewPassword = (req, res) => {
  let message = req.flash('error');
  if (message.length > 0) {
    message = message[0];
  } else {
    message = null;
  }

  res.render('auth/new-password', {
    path:'/new-password',
    pageTitle: 'New Password',
    errorMessage: message
  });
}
