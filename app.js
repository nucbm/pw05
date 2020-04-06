const express = require('express');
const exphbs = require('express-handlebars');
const cookieParser = require('cookie-parser');
var session = require('express-session');

const crypto = require('crypto');
const app = express();
const authTokens = {};

const users = [
    // This user is added to the array to avoid creating new user on each restart
    {
        firstName: 'John',
        lastName: 'Doe',
        email: 'johndoe@email.com',
        // This is the SHA256 hash for value of `password`
        password: 'XohImNooBHFR0OVvjcYpJ3NgPQ1qq73WKhHvch0VQtg='
    }
];




const getHashedPassword = (password) => {
    const sha256 = crypto.createHash('sha256');
    const hash = sha256.update(password).digest('base64');
    return hash;
}

const getUrlImg = (emailAddress, options ={} ) => {
    console.log(emailAddress);
    //var emailAddrss = 'costea.c@gmail.com';
    const defaultImage = options.defaultImage || 'identicon';
    const emailHash = crypto.createHash('md5').update(emailAddress).digest('hex');
    return `https://www.gravatar.com/avatar/${emailHash}?d=${defaultImage}`;
}


const generateAuthToken = () => {
    return crypto.randomBytes(30).toString('hex');
}

// express 4.16, parse URL-encoded bodies
app.use(express.urlencoded({ extended: true })); 

app.use(cookieParser());

// Use the session middleware
app.use(session({
    secret: 'redcat', 
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60000 }
  }))

app.use((req, res, next) => {
    const authToken = req.cookies['AuthToken'];
    req.user = authTokens[authToken];
    next();
});

app.engine('hbs', exphbs({
   extname: '.hbs'
}));

app.set('view engine', 'hbs');

app.get('/', (req, res) => {
    res.render('home');
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const hashedPassword = getHashedPassword(password);

    const user = users.find(u => {
        return u.email === email && hashedPassword === u.password
    });

    if (user) {
        const authToken = generateAuthToken();
        authTokens[authToken] = email;
        res.cookie('AuthToken', authToken);
        res.redirect('/protected');
        return;
    } else {
        res.render('login', {
            message: 'Invalid username or password',
            messageClass: 'alert-danger'
        });
    }
});

app.get('/register', (req, res) => {
    res.render('register');
});


app.post('/register', (req, res) => {
    const { email, firstName, lastName, password, confirmPassword } = req.body;

    if (password === confirmPassword) {
        if (users.find(user => user.email === email)) {

            res.render('register', {
                message: 'User already registered.',
                messageClass: 'alert-danger'
            });

            return;
        }

        const hashedPassword = getHashedPassword(password);

        users.push({
            firstName,
            lastName,
            email,
            password: hashedPassword
        });

        res.render('login', {
            message: 'Registration Complete. Please login to continue.',
            messageClass: 'alert-success'
        });
    } else {
        res.render('register', {
            message: 'Password does not match.',
            messageClass: 'alert-danger'
        });
    }
});


app.get('/protected', (req, res) => {
    if (req.user) {
        const urlimg = getUrlImg(req.user);

        if (req.session.views) {
            req.session.views++
          } else {
            req.session.views = 1
          }
        res.render('protected', {mailuser: req.user,  viewsno : req.session.views, myavatar: urlimg});
    } else {
        res.render('login', {
            message: 'Please login to continue',
            messageClass: 'alert-danger'
        });
    }
});


// logout
app.get('/logout', function(req, res, next) {
    console.log('user logout'); 
    res.clearCookie('AuthToken');
    if (req.session) { 
      // delete session object
      req.session.destroy(function(err) {
        if(err) {
          return next(err);
        } else {
          return res.redirect('/');
        }
      });
    } 
});


app.listen(3000, () => console.log('Server running on port 3000'));
