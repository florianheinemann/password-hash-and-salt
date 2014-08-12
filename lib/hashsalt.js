'use strict';

var crypto = require('crypto');

var iterations = 10000;
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
				crypto.pbkdf2(password, salt, iterations, 64, function(err, key) {
					if(err)
						return callback(err);
					var res = 'pbkdf2$' + iterations + 
								'$' + key.toString('hex') + 
								'$' + salt.toString('hex');
					callback(null, res);
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

		verifyAgainst: function(hashedPassword, callback) {
			if(!hashedPassword || !password)
				return callback(null, false);

			var key = hashedPassword.split('$');
			if(key.length !== 4 || !key[2] || !key[3])
				return callback('Hash not formatted correctly');

			if(key[0] !== 'pbkdf2' || key[1] !== iterations.toString())
				return callback('Wrong algorithm and/or iterations');

			this.hash(key[3], function(error, newHash) {
				if(error)
					return callback(error);
				callback(null, newHash === hashedPassword);				
			});	
		}
	};
}


module.exports = password;