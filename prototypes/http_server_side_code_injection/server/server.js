const express = require('express');
const cookie_parser = require('cookie-parser');
const escape = require('escape-html');
const serialize = require('node-serialize');
const body_parser = require('body-parser');

const serv = express();
const rout = express.Router();

const port = 8090;

serv.use(body_parser.urlencoded({
    extended: true
}));

serv.set('view engine', 'ejs');

serv.use(body_parser.json());
serv.use(cookie_parser());
serv.use('/', rout);

rout.get('/', (req, res) => {
    console.log('Hit login page: "/"');
    res.status(200).sendfile('views/login.html');
});

rout.get('/app', (req, res) => {
    console.log('Hit app page: "/"');
    if (!req.cookies.user) {
        console.log('No Token, Redirecting...');
        res.redirect('/victim1');
    }
    else{
        console.log('Token, Staying');
        var encoded_cookie_str = new Buffer(req.cookies.user, 'base64').toString();
        var dict = serialize.unserialize(encoded_cookie_str);
        //res.status(200).send('Hello, ' + escape(dict.u) + '<a href="/victim2/unauth">logout</a>');
        //res.sendfile('username.html');
        res.render('user', {username: dict['u']});
    }
    
});

rout.get('/unauth', (req, res) => {
    console.log('Hit unauth page: "/unauth"');
    if (req.cookies.user) {
        res.clearCookie('user', { maxAge: 90000, httpOnly: false, secure: false, sameSite: "Lax" });
    }
    res.redirect('/victim1');
});

rout.post('/auth', (req, res) => {

    console.log('Hit auth page: "/auth"');

    if (req.cookies.user) {
        console.log('Cookie Detected, Clearing...');
        res.clearCookie('user', { maxAge: 90000, httpOnly: false, secure: false, sameSite: "Lax" });
    }
    
    if (req.body.u)
    {
        console.log('Cookie either Cleared or None, Creating...');
        var body = JSON.stringify(req.body);
        var encoded_cookie_str = new Buffer(body).toString('base64');
        res.cookie('user', encoded_cookie_str, {
            maxAge: 90000,
            httpOnly: false,
            secure: false,
            sameSite: 'lax'
        });
        console.log('Cookie: ' + encoded_cookie_str);
        console.log('Sending Cookie..');
    }

    res.status(200).send();    
    //res.end('test');
});

serv.listen(port, '0.0.0.0', () => {
    console.log('Server is running on port ' + port);
});
