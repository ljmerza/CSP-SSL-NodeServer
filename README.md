# CSP-SSL-NodeServer

##### This server uses various CSP techniques using the helmet package. It also uses 
csurf tokens for form handling with the csurf package, and enforces SSL with the 
express-enforces-ssl package. It also properly handles serect keys through arguments.

Security setting recommendations taken from [Mozilla CSP](https://developer.mozilla.org/en-US/docs/Web/Security/CSP/CSP_policy_directives#media-src) and [the CSP website](http://content-security-policy.com/)

##### The flowing helmet options are used:

* CSP options for only allowing js/css/html/images/fonts/ajax from same origin domain 
while blocking any media,
or applets. Will POST request CSP violations to a given path. 
* Disables CSP for Android
* Disables browser sniffing to deter detection of underlying framework used to power server
* Enables XSS filters
* Disables allowing pages in iframes
* Sets Strict-Transport-Security header to only allow HTTPS for set period of time
* Prevents IE from opening untrusted HTML
* Disable browser sniffing of mimetypes
* Disables browser caching of web pages
* Disables caching of dns lookups
