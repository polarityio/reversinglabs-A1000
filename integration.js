'use strict';

let request = require('postman-request');
let async = require('async');
let Logger;

let requestWithDefaults;

const authTokens = new Map();

function startup(logger) {
  Logger = logger;
  let defaults = {
    json: true
  };

  requestWithDefaults = request.defaults(defaults);
}

function _createAuthKey(options) {
  return options.username + options.password;
}

function createToken(options, cb) {
  let authKey = _createAuthKey(options);
  if (authTokens.has(authKey)) {
    Logger.trace({ user: options.username }, 'Using Cached Auth Token');
    cb(null, authTokens.get(authKey));
    return;
  }

  let requestOptions = {
    uri: options.url + '/api-token-auth/',
    method: 'POST',
    body: {
      username: options.username,
      password: options.password
    }
  };

  requestWithDefaults(requestOptions, function (err, response, body) {
    let errorObject = _isApiError(err, response, body);
    if (errorObject) {
      cb(errorObject);
      return;
    }
    Logger.trace({ body }, 'Checking the token body');
    let authToken = response.body.token;
    authTokens.set(authKey, authToken);
    cb(null, authToken);
  });
}

function doLookup(entities, options, cb) {
  Logger.debug({ entities, options }, 'Options');

  options.url = options.url.endsWith('/') ? options.url.slice(0, -1) : options.url;
  
  let lookupResults = [];

  createToken(
    options,
    function (err, token) {
      if (err) {
        cb(err);
        return;
      }
      
      // Split entities by hash type
      let md5Entities = entities.filter((entity) => entity.isMD5);
      let sha1Entities = entities.filter((entity) => entity.isSHA1);
      let sha256Entities = entities.filter((entity) => entity.isSHA256);
      
      // Create lookup tasks for each hash type that has entities
      const lookupTasks = [];
      
      if (md5Entities.length > 0) {
        lookupTasks.push((next) => {
          _lookupEntities(md5Entities, 'md5', options, token, next);
        });
      }
      
      if (sha1Entities.length > 0) {
        lookupTasks.push((next) => {
          _lookupEntities(sha1Entities, 'sha1', options, token, next);
        });
      }
      
      if (sha256Entities.length > 0) {
        lookupTasks.push((next) => {
          _lookupEntities(sha256Entities, 'sha256', options, token, next);
        });
      }
      
      // If no entities to lookup, return empty results
      if (lookupTasks.length === 0) {
        Logger.trace('No entities to look up');
        cb(null, []);
        return;
      }
      
      // Run all lookups in parallel
      async.parallel(lookupTasks, (err, results) => {
        if (err) {
          cb(err);
          return;
        }
        
        // Concatenate all results
        results.forEach((result) => {
          lookupResults = lookupResults.concat(result);
        });
        
        Logger.trace({ lookupResults }, 'Lookup Results');
        cb(null, lookupResults);
      });
    },
    function (err) {
      cb(err, lookupResults);
    }
  );
}

function _lookupEntities(entities, entityType, options, token, cb) {
  let requestOptions = {
    uri: options.url + '/api/samples/list/',
    method: 'POST',
    headers: { Authorization: 'Token ' + token },
    body: {
      hash_values: entities.map((entity) => entity.value),
      fields: [
        entityType,
        'category',
        'ticore',
        'ticloud',
        'summary',
        'aliases',
        'file_type',
        'identification_name',
        'extracted_file_count',
        'threat_status',
        'threat_level',
        'threat_name',
        'trust_factor',
        'classification_reason',
        'local_first_seen',
        'local_last_seen'
      ]
    }
  };

  requestWithDefaults(requestOptions, function (err, response, body) {
    let errorObject = _isApiError(
      err,
      response,
      body,
      entities.map((entity) => entity.value)
    );
    if (errorObject) {
      cb(errorObject);
      return;
    }

    if (body === null || !body.results || body.results.length === 0) {
      cb(
        null,
        entities.map((entity) => {
          return {
            entity: entity,
            data: null
          };
        })
      );
      return;
    }

    let threatData = [];

    body.results.forEach(function (result) {
      threatData.push(result.threat_name);
      threatData.push(result.threat_status);
    });

    Logger.trace({ threatData: threatData }, 'ThreatData');
    Logger.trace(
      { results: body.results.map((result) => result[entityType]) },
      'results of lookup'
    );

    let valueToResults = {};
    body.results.forEach((result) => {
      if (result[entityType]) {
        let key = result[entityType].toLowerCase();
        if (!valueToResults[key]) {
          valueToResults[key] = [];
        }
        valueToResults[key].push(result);
      }
    });

    if (_isLookupMiss(response)) {
      cb(
        null,
        entities.map((entityObj) => {
          return {
            entity: entityObj,
            data: null
          };
        })
      );
      return;
    }

    // The lookup results returned is an array of lookup objects with the following format
    cb(
      null,
      entities.map((entity) => {
        let key = entity.value.toLowerCase();
        if (!valueToResults[key]) {
          return {
            entity: entity,
            data: null
          };
        } else {
          return {
            entity: entity,
            data: {
              summary: threatData,
              details: valueToResults[key]
            }
          };
        }
      })
    );
  });
}

function _isLookupMiss(response) {
  return response.statusCode === 404;
}

function _isApiError(err, response, body) {
  if (err) {
    return err;
  }

  if (response.statusCode === 500) {
    return _createJsonErrorPayload(
      'Malinformed Request',
      null,
      '500',
      '1',
      'Malinformed Request',
      {
        err: err
      }
    );
  }

  // Any code that is not 200 and not 404 (missed response), we treat as an error
  if (response.statusCode !== 200 && response.statusCode !== 404) {
    return body;
  }

  return null;
}

// function that takes the ErrorObject and passes the error message to the notification window
function _createJsonErrorPayload(msg, pointer, httpCode, code, title, meta) {
  return {
    errors: [_createJsonErrorObject(msg, pointer, httpCode, code, title, meta)]
  };
}

function _createJsonErrorObject(msg, pointer, httpCode, code, title, meta) {
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
}

function validateOptions(userOptions, cb) {
  let errors = [];

  if (
    typeof userOptions.url.value !== 'string' ||
    (typeof userOptions.url.value === 'string' && userOptions.url.value.trim().length === 0)
  ) {
    errors.push({
      key: 'url',
      message: 'You must provide a valid Spectra Analyze URL'
    });
  }

  if (
    typeof userOptions.password.value !== 'string' ||
    (typeof userOptions.password.value === 'string' && userOptions.password.value.trim().length === 0)
  ) {
    errors.push({
      key: 'password',
      message: 'You must provide a valid password'
    });
  }

  if (
    typeof userOptions.username.value !== 'string' ||
    (typeof userOptions.username.value === 'string' && userOptions.username.value.trim().length === 0)
  ) {
    errors.push({
      key: 'username',
      message: 'You must provide a Spectra Analyze Username'
    });
  }

  cb(null, errors);
}

module.exports = {
  doLookup,
  startup,
  validateOptions
};
