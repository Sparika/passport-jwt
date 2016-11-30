var passport = require('passport-strategy')
    , auth_hdr = require('./auth_header')
    , util = require('util')
    , url = require('url')
    , request = require('request')
    , jwt = require('jsonwebtoken')
    , atob = require('atob')
    , jwk2pem = require('pem-jwk').jwk2pem;



/**
 * Strategy constructor
 *
 * @param options
 *          secretOrKey: String or buffer containing the secret or PEM-encoded public key. Required if keyInHeader is false.
 *          keyInHeader: Boolean indicating if the key can be provided in the JWT Header following JWK RFC7515.  Default to false.
 *          jwtFromRequest: (REQUIRED) Function that accepts a reqeust as the only parameter and returns the either JWT as a string or null
 *          issuer: If defined issuer will be verified against this value. OVERRIDEN if keyInHeader is true.
 *                  In that case, the issuer is set to the jku domain name so that it must match with iss.
 *          audience: If defined audience will be verified against this value
 *          algorithms: List of strings with the names of the allowed algorithms. For instance, ["HS256", "HS384"].
 *          ignoreExpiration: if true do not validate the expiration of the token.
 *          passReqToCallback: If true the, the verify callback will be called with args (request, jwt_payload, done_callback).
 * @param verify - Verify callback with args (jwt_payload, done_callback) if passReqToCallback is false,
 *                 (request, jwt_payload, done_callback) if true.
 */
function JwtStrategy(options, verify) {

    passport.Strategy.call(this);
    this.name = 'jwt';

    this._secretOrKey = options.secretOrKey;

    this._keyInHeader = options.keyInHeader || false;

    if (!this._secretOrKey && !this._keyInHeader) {
        throw new TypeError('JwtStrategy requires a secret, a key, or the keyInHeader option set to true.');
    }

    if (this._secretOrKey && this._keyInHeader){
        throw new TypeError('JwtStrategy requires that keyInHeader be set to false if a key is provided.')
    }

    this._verify = verify;
    if (!this._verify) {
        throw new TypeError('JwtStrategy requires a verify callback');
    }

    this._jwtFromRequest = options.jwtFromRequest;
    if (!this._jwtFromRequest) {
        throw new TypeError('JwtStrategy requires a function to retrieve jwt from requests (see option jwtFromRequest)');
    }

    this._passReqToCallback = options.passReqToCallback;
    this._verifOpts = {};

    if (options.issuer) {
        this._verifOpts.issuer = options.issuer;
    }

    if(this._keyInHeader && !this._verifOpts.issuer){
        throw new TypeError('JwtStrategy requires an issuer to verify if keyInHeader is set to true.')
    }

    if (options.audience) {
        this._verifOpts.audience = options.audience;
    }

    if (options.algorithms) {
        this._verifOpts.algorithms = options.algorithms;
    }

    if (options.ignoreExpiration != null) {
        this._verifOpts.ignoreExpiration = options.ignoreExpiration;
    }

};
util.inherits(JwtStrategy, passport.Strategy);



/**
 * Allow for injection of JWT Verifier.
 *
 * This improves testability by allowing tests to cleanly isolate failures in the JWT Verification
 * process from failures in the passport related mechanics of authentication.
 *
 * Note that this should only be replaced in tests.
 */
JwtStrategy.JwtVerifier = require('./verify_jwt');



/**
 * Authenticate request based on JWT obtained from header or post body
 */
JwtStrategy.prototype.authenticate = function(req, options) {
    var self = this;

    var token = self._jwtFromRequest(req);

    if (!token) {
        return self.fail(new Error("No auth token"));
    }

    function verifyCallback(jwt_err, payload) {
        if (jwt_err) {
            console.log(jwt_err)
            return self.fail(jwt_err);
        } else {
            // Pass the parsed token to the user
            var verified = function(err, user, info) {
                console.log('verified')
                console.log(err)
                console.log(user)
                console.log(info)
                if(err) {
                    return self.error(err);
                } else if (!user) {
                    return self.fail(info);
                } else {
                    return self.success(user, info);
                }
            };

            try {
                if (self._passReqToCallback) {
                    self._verify(req, payload, verified);
                } else {
                    self._verify(payload, verified);
                }
            } catch(ex) {
                self.error(ex);
            }
        }
    }

    if(self._keyInHeader){
        // Get key from header and verify
        //TODO solve issue with jwt decode
        var header = JSON.parse(atob(token.split('.')[0]))
        // Get JKU from token header
        // TODO support KID
        var jku = header.jku
        if(!jku){
            console.log('No JKU found in token')
            self.fail(new Error('No JKU found in token'))
        }

        if(!jku.startsWith('https')){
            console.log('JKU is unsecure, no HTTPS')
            self.fail(new Error('JKU is unsecure, no HTTPS'))
        }
        self._verifOpts.issuer = 'https://'+jku.split('/')[2]

        request(jku, function(error, response, body) {
            if(error){
                console.log(error)
                return self.fail(error)
            }

            //TODO support KID
            // Generate key from JWK
            //this._secretOrKey = 'LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlHZk1BMEdDU3FHU0liM0RRRUJBUVVBQTRHTkFEQ0JpUUtCZ1FDOHpPUFBjYVh4dDA5S2RXWjJpZDU0Y2NYUwpTQTIyU3V6bkd2bFlIMkxqSE85ZGUwWjJNdkZraklaeDZnQlNVMGNuTTllalpVNmFFNlNyWkt0VGhTT0xWcmJGCitySmJtWmVOYW0zUU9jdmNyUVBLNlJZZzZ5dlFiSkNRRTNOZGhCQi91cnpqVVRnN3ZmVzhPQk1PdzJqVHFtY3YKT0hRWFR0SVZyci9nQlVxYVJRSURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo='
            this._secretOrKey = jwk2pem(JSON.parse(body).keys[0])
            // Verify the JWT
            JwtStrategy.JwtVerifier(token, this._secretOrKey, this._verifOpts, verifyCallback);
        });
    }
    else {
        // Verify the JWT
        JwtStrategy.JwtVerifier(token, this._secretOrKey, this._verifOpts, verifyCallback);
    }


};



/**
 * Export the Jwt Strategy
 */
 module.exports = JwtStrategy;
