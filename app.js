'use strict'

let express = require("express"),
  session = require("express-session"),
  bodyParser = require("body-parser"),
  csrf = require("csurf"),
  helmet = require('helmet'),
  http = require('http'),
  ms = require('ms'), // allows for human friendly time setting
  expressEnforcesSSL = require('express-enforces-ssl') // enforces HTTPS on any incoming requests

let app = express()

app.enable('trust proxy')
app.set("view engine", "jade")
app.set('port', process.env.PORT || 3000)

app.use(session({
  secret: "dfg3456%$^$TRHGehte345yh%Y$Hdehy$hjrtHEThwr",
  resave: false,
  saveUninitialized: true
}))
app.use(bodyParser.urlencoded({
  extended: false // only allow arrays and strings
}))

app.use(expressEnforcesSSL())





/***************************helmet security options******************************/

/*dont allow pages in ANY iframes - can also do 
'sameorigin' for only iframes for same domain only*/
app.use(helmet.frameguard({ action: 'deny' }))

/*Content security policies see content-security-policy.com/
for more options */
app.use(helmet.csp({
  directives: {
    /* with the below js/css/img/connect settings, only allows
    images, scripts, ajax, and css from same origin and doesnt allow
    any other resources to load such as objects, frames, and media
    even from same origin ie your domain*/

    defaultSrc: 'none', // dont allow anything except for below settings
    // sets scripts to same origin and google analytics only
    scriptSrc: ['self', 'www.google-analytics.com'], 
    styleSrc: 'self', // sets css to same origin only
    connectSrc: 'self', // sets ajax to same origin only
    imgSrc: 'self',
    fontSrc: 'self', // sets images to same origin only
    /*enables a sandbox for requested source only 
    allowing forms and scripts to execute*/
    sandbox: ['allow-forms', 'allow-scripts'], 
    // sends a POST request to path given with a report if there is a policy violation
    reportUri: '/report-violation', 
 
    objectSrc: [], // empty array = no plugins allow - ie object, embed, applet
  },
  // Set to true if you only want browsers to report errors not block them 
  reportOnly: false,
  // Set to true if you want to blindly set all headers: Content-Security-Policy, 
  // X-WebKit-CSP, and X-Content-Security-Policy. 
  setAllHeaders: false,
  // disables CSP on Android - can be unstable on Android. 
  disableAndroid: true,
  // disables any user-agent sniffing - faster headers but less compatible with older browsers
  browserSniff: false
}))

// prevent XSS attacks by setting the X-XSS-Protection header 
app.use(helmet.xssFilter())

/* HTTP Strict Transport Security - only allow HTTPS doesnt switch users 
to https only tell https users to continue using https*/
app.use(helmet.hsts({
  // visit by https for the next year
  maxAge: ms("1 year"),
  // incude any subdomains for https only
  includeSubdomains: true
}))

/*Hide the X-Powered-By header so clients dont know you are using express
use setTo option to change name manually*/
app.use(helmet.hidePoweredBy())

/*sets X-Download-Options header to noopen to prevent IE users from
executing downloads in your site's context*/
app.use(helmet.ieNoOpen())

/*sets X-Content-Type-Options header so the browser wont try to autodetect
any file's mimetype and execute code not meant to be executed*/
app.use(helmet.noSniff())

// disable browser caching
app.use(helmet.noCache())

// disable prefetching of dns lookups - hurts performance
app.use(helmet.dnsPrefetchControl())







app.use(csrf())

app.get("/", function(req, res) {
  res.render("index", {
    csrfToken: req.csrfToken()
  })
})

app.post("/submit", function(req, res) {
  res.send("Form submission worked!")
})

app.use(function(err, req, res, next) {
  if (err.code !== "EBADCSRFTOKEN") {
    return next(err)
  }
  res.status(403)
  res.send("CSRF error.")
})

app.use(function(err, req, res, next) {
  res.status(500)
  res.send("Non-CSRF error.")
})

http.createServer(app).listen(app.get('port'), function() {
    console.log('Express server listening on port ' + app.get('port'));
})
