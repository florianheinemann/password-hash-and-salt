'use strict';

var crypto = require('crypto');

var password = function(password) {
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

			if(typeof salt === 'string') {
				salt = new Buffer(salt, 'hex');
			}

			var calcHash = function() {
				crypto.pbkdf2(password, salt, 10000, 64, function(err, key) {
					if(err)
						return callback(err);
					callback(null, key.toString('hex'), salt.toString('hex'));
				})		
			};

			if(!salt) {
				crypto.randomBytes(64, function(err, gensalt) {
					if(err)
						return callback(err);
					salt = gensalt;
					calcHash();
				});		
			} else {
				calcHash();
			}			
		},

		verifyAgainst: function(hashedPassword, salt, callback) {
			if(!hashedPassword || !password)
				return callback(null, false);
			if(!salt)
				return callback('No salt provided');

			this.hash(salt, function(error, newHash, newSalt) {
				if(error)
					return callback(error);
				callback(null, newHash === hashedPassword);				
			});	
		}
	};
}


module.exports = password;