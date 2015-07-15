'use strict';

var crypto = require('crypto');

var DEFAULT_ITERATIONS = 10000;
var DEFAULT_REHASH = false;
var password = function(password, iterations, rehash) {
	iterations = (typeof(iterations) === 'undefined') ? DEFAULT_ITERATIONS : iterations;
	rehash = (typeof(rehash) === 'undefined') ? DEFAULT_REHASH : rehash;
	
	var calcHash = function(hashSalt, hashIterations, callback){
		if(typeof hashSalt === 'string') {
			hashSalt = new Buffer(hashSalt, 'hex');
		}
		crypto.pbkdf2(password, hashSalt, hashIterations, 64, function(err, key) {
			if(err)
				return callback(err);
			var res = 'pbkdf2$' + hashIterations + 
						'$' + key.toString('hex') + 
						'$' + hashSalt.toString('hex');
			callback(null, res);
		});
	};
	
	return {
		hash: function(salt, callback) {
			// Make salt optional
			if(callback === undefined && salt instanceof Function) {
				callback = salt;
				salt = undefined;
			}

			if(!password) {
				return callback('No password provided')
			}

			if(!salt) {
				crypto.randomBytes(64, function(err, gensalt) {
					if(err)
						return callback(err);
					salt = gensalt;
					calcHash(salt, iterations, callback);
				});		
			} else {
				calcHash(salt, iterations, callback);
			}			
		},

		verifyAgainst: function(hashedPassword, callback) {
			if(!hashedPassword || !password)
				return callback(null, false);

			var key = hashedPassword.split('$');
			if(key.length !== 4 || !key[2] || !key[3])
				return callback('Hash not formatted correctly');

			if(key[0] !== 'pbkdf2')
				return callback('Wrong algorithm');
			
			if(key[1] !== iterations.toString() && (!rehash))
				return callback ('Wrong number of iterations and rehash not specified');

			calcHash(key[3], parseInt(key[1]), function(error, matchHash) {
				if(error)
					return callback(error);
				if(matchHash === hashedPassword){
					if(key[1] !== iterations.toString()){
						//rehash the password and use as third argument to callback
						calcHash(key[3], iterations, function(error, newHash){
							if(error)
								return callback(error);
							callback(null, true, newHash);
						});
					}else{
						//hash matches, no rehash needed
						callback(null, true);				
					}
				}else{	
					//hashes don't match
					callback(null, false);
				}
			});	
		}
	};
}


module.exports = password;