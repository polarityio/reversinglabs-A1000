'use strict';

let request = require('request');
let _ = require('lodash');
let util = require('util');
let async = require('async');
let fs = require('fs');
let config = require('./config/config');
let Logger;

let requestWithDefaults;

const authTokens = new Map();


function startup(logger) {
    Logger = logger;
    let defaults = {};


    if (typeof config.request.cert === 'string' && config.request.cert.length > 0) {
        defaults.cert = fs.readFileSync(config.request.cert);
    }

    if (typeof config.request.key === 'string' && config.request.key.length > 0) {
        defaults.key = fs.readFileSync(config.request.key);
    }

    if (typeof config.request.passphrase === 'string' && config.request.passphrase.length > 0) {
        defaults.passphrase = config.request.passphrase;
    }

    if (typeof config.request.ca === 'string' && config.request.ca.length > 0) {
        defaults.ca = fs.readFileSync(config.request.ca);
    }

    if (typeof config.request.proxy === 'string' && config.request.proxy.length > 0) {
        defaults.proxy = config.request.proxy;
    }

    if (typeof config.request.rejectUnauthorized === 'boolean') {
        defaults.rejectUnauthorized = config.request.rejectUnauthorized;
    }

    requestWithDefaults = request.defaults(defaults);
}

function _createAuthKey(options){
    return options.username + options.password;
}

var createToken = function (options, cb) {
    let authKey = _createAuthKey(options);
    if(authTokens.has(authKey)){
        Logger.trace({user: options.username}, 'Using Cached Auth Token');
        cb(null, authTokens.get(authKey));
        return;
    }

    let requestOptions = {
        uri: options.url + '/api-token-auth/',
        method: 'POST',
        body: {
            "username": options.username,
            "password": options.password
        },
        json: true
    };

    requestWithDefaults(requestOptions, function (err, response, body) {
        let errorObject = _isApiError(err, response, body);
        if (errorObject) {
            cb(errorObject);
            return;
        }
        Logger.trace({body: response.body.token}, "Checking the token body");
        let authToken = response.body.token;
        authTokens.set(authKey, authToken);
        cb(null, authToken);
    });
};

function doLookup(entities, options, cb) {

    Logger.debug({options: options}, 'Options');


    let lookupResults = [];
    let entityObj = entities;

    createToken(options, function (err, token) {

        async.each(entities, function (entityObj, next) {
            if (entityObj.isSHA1 && options.lookupSha1) {
                _lookupEntitySHA1(entityObj, options, token, function (err, result) {
                    if (err) {
                        next(err);
                    } else {
                        Logger.debug({results: result}, "Logging SHA1 Results");
                        lookupResults.push(result);
                        next(null);
                    }
                });
            } else if (entityObj.isSHA256 && options.lookupSha256) {
                _lookupEntitySHA256(entityObj, options, token, function (err, result) {
                    if (err) {
                        next(err);
                    } else {
                        Logger.debug({results: result}, "Logging SHA256 Results");
                        lookupResults.push(result);
                        next(null);
                    }
                });
            } else if (entityObj.isMD5 && options.lookupMd5) {
                _lookupEntityMD5(entityObj, options, token, function (err, result) {
                    if (err) {
                        next(err);
                    } else {
                        Logger.debug({results: result}, "Logging MD5 Results");
                        lookupResults.push(result);
                        next(null);
                    }
                });
            } else {
                lookupResults.push({entity: entityObj, data: null}); //Cache the missed results
                next(null);
            }
        }, function (err) {
            cb(err, lookupResults);
        });
    });
}

function _lookupEntitySHA1(entityObj, options, token, cb) {
    let requestOptions = {
        uri: options.url + '/api/samples/list/',
        method: 'POST',
        headers: {'Authorization': 'Token ' + token},
        body: {
              "hash_values": [entityObj.value],
              "fields": ["sha1",
              "category",
              "ticore",
              "ticloud",
              "summary",
              "aliases",
              "file_type",
              "identification_name",
              "extracted_file_count",
          "threat_status",
          "threat_level",
          "threat_name",
          "trust_factor",
          "classification_reason",
          "local_first_seen",
          "local_last_seen"
        ]
      },
        json: true
    };


    requestWithDefaults(requestOptions, function (err, response, body) {
        let errorObject = _isApiError(err, response, body, entityObj.value);
        if (errorObject) {
            cb(errorObject);
            return;
        }

        //Logger.debug({data: body.content[0]}, "Logging Body Data");
        if (_.isNull(body) || _.isEmpty(body.results)){
          cb(null, {
              entity: entityObj,
              data: null
          });
          return;
        }

        let threatData = [];

        body.results.forEach(function(result){
          threatData.push(result.threat_name),
          threatData.push(result.threat_status)
        });

        Logger.trace({threatData: threatData}, "ThreatData");

        if (_isLookupMiss(response)) {
            cb(null, {
                entity: entityObj,
                data: null
            });
            return;
        }


        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // We are constructing the tags using a custom summary block so no data needs to be passed here
                summary: threatData,
                // Data that you want to pass back to the notification window details block
                details: body
            }
        });
    });
}

function _lookupEntitySHA256(entityObj, options, token, cb) {
    let requestOptions = {
        uri: options.url + '/api/samples/list/',
        method: 'POST',
        headers: {'Authorization': 'Token ' + token},
        body: {
              "hash_values": [entityObj.value],
              "fields": ["sha256",
              "category",
              "ticore",
              "ticloud",
              "summary",
              "aliases",
              "file_type",
              "identification_name",
              "extracted_file_count",
          "threat_status",
          "threat_level",
          "threat_name",
          "trust_factor",
          "classification_reason",
          "local_first_seen",
          "local_last_seen"
        ]
      },
        json: true
    };


    requestWithDefaults(requestOptions, function (err, response, body) {
        let errorObject = _isApiError(err, response, body, entityObj.value);
        if (errorObject) {
            cb(errorObject);
            return;
        }

        //Logger.debug({data: body.content[0]}, "Logging Body Data");
        if (_.isNull(body) || _.isEmpty(body.results)){
          cb(null, {
              entity: entityObj,
              data: null
          });
          return;
        }

        if (_isLookupMiss(response)) {
            cb(null, {
                entity: entityObj,
                data: null
            });
            return;
        }

        let threatData = [];

        body.results.forEach(function(result){
          threatData.push(result.threat_name),
          threatData.push(result.threat_status)
        });

        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // We are constructing the tags using a custom summary block so no data needs to be passed here
                summary: threatData,
                // Data that you want to pass back to the notification window details block
                details: body
            }
        });
    });
}

function _lookupEntityMD5(entityObj, options, token, cb) {
    let requestOptions = {
        uri: options.url + '/api/samples/list/',
        method: 'POST',
        headers: {'Authorization': 'Token ' + token},
        body: {
              "hash_values": [entityObj.value],
              "fields": ["md5",
              "category",
              "ticore",
              "ticloud",
              "summary",
              "aliases",
              "file_type",
              "identification_name",
              "extracted_file_count",
          "threat_status",
          "threat_level",
          "threat_name",
          "trust_factor",
          "classification_reason",
          "local_first_seen",
          "local_last_seen"
        ]
      },
        json: true
    };


    requestWithDefaults(requestOptions, function (err, response, body) {
        let errorObject = _isApiError(err, response, body, entityObj.value);
        if (errorObject) {
            cb(errorObject);
            return;
        }

        //Logger.debug({data: body.content[0]}, "Logging Body Data");
        if (_.isNull(body) || _.isEmpty(body.results)){
          cb(null, {
              entity: entityObj,
              data: null
          });
          return;
        }

        if (_isLookupMiss(response)) {
            cb(null, {
                entity: entityObj,
                data: null
            });
            return;
        }

        let threatData = [];

        body.results.forEach(function(result){
          threatData.push(result.threat_name),
          threatData.push(result.threat_status)
        });

        // The lookup results returned is an array of lookup objects with the following format
        cb(null, {
            // Required: This is the entity object passed into the integration doLookup method
            entity: entityObj,
            // Required: An object containing everything you want passed to the template
            data: {
                // We are constructing the tags using a custom summary block so no data needs to be passed here
                summary: threatData,
                // Data that you want to pass back to the notification window details block
                details: body
            }
        });
    });
}

function _isLookupMiss(response) {
    return response.statusCode === 404 || response.statusCode === 500;
}

function _isApiError(err, response, body, entityValue) {
    if (err) {
        return err;
    }

    if (response.statusCode === 500) {
        return _createJsonErrorPayload("Malinformed Request", null, '500', '1', 'Malinformed Request', {
            err: err
        });
    }

    // Any code that is not 200 and not 404 (missed response), we treat as an error
    if (response.statusCode !== 200 && response.statusCode !== 404) {
        return body;
    }

    return null;
}

// function that takes the ErrorObject and passes the error message to the notification window
var _createJsonErrorPayload = function (msg, pointer, httpCode, code, title, meta) {
    return {
        errors: [
            _createJsonErrorObject(msg, pointer, httpCode, code, title, meta)
        ]
    }
};

var _createJsonErrorObject = function (msg, pointer, httpCode, code, title, meta) {
    let error = {
        detail: msg,
        status: httpCode.toString(),
        title: title,
        code: 'RLA_' + code.toString()
    };

    if (pointer) {
        error.source = {
            pointer: pointer
        };
    }

    if (meta) {
        error.meta = meta;
    }

    return error;
};


module.exports = {
    doLookup: doLookup,
    startup: startup
};
