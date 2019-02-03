var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const bodyParser = require('body-parser');
const session = require('express-session');
const DynamoDBStore = require('connect-dynamodb')(session);
const csrf = require('csurf');
const flash = require('connect-flash');

const AWS = require('aws-sdk');
AWS.config.update({region: 'us-east-1'});

var adminRouter = require('./routes/admin');
var shopRouter = require('./routes/shop');
var authRouter = require('./routes/auth');

const User = require('./models/users');

var app = express();

//sets session DynamoDB database info
const DynamoDBStoreOptions = {
  table: 'sessions',
  AWSConfigJSON: {
    region: 'us-east-1'
  }
}
const csrfProtection = csrf();
app.use(flash());

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  store: new DynamoDBStore(DynamoDBStoreOptions),
  secret: 'd1ef2473-4854-4c91-9bd3-ba924925db73',
  resave: false,
  saveUninitialized: false,
  cookie: {maxAge: 360000}
}));
app.use(csrfProtection);

//sets user
app.use((req, res, next) => {
  if (!req.session.user) {
    next();
  } else {
    User.findById(req.session.user.email)
      .then(user => {
        user = user.Item;
        if (Object.entries(user).length === 0) {
          return next();
        }
        req.user = new User(user.name, user.email, user.password, user.resetToken, user.resetTokenExpiration, user.store_location, user.cart);
        next();
      })
      .catch((err) => {
        throw new Error(err);
      });
  }
});

//sets local attributes to be used in .ejs files
app.use((req, res, next) => {
  res.locals.isAuthenticated = req.session.isLoggedIn;
  res.locals.csrfToken = req.csrfToken();
  if(typeof(req.user) !== 'undefined') {
    if(typeof(req.user.name) !== 'undefined') {
      res.locals.userName = req.user.name;
    } else {
      res.locals.userName = req.user.email;
    }
  }
  next();
});

app.use('/admin', adminRouter);
app.use(shopRouter);
app.use(authRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
