'use strict';

// var password = require('password-hash-and-salt');
var password = require('../index');

var myuser = [];

// Creating hash and salt
password('mysecret').hash(function(error, hash, salt) {
	if(error)
		throw new Error('Something went wrong!');

	// Store hash and salt
	myuser.hash = hash;
	myuser.salt = salt; // Salt can be stored as it is along with the user

	// Verifying a hash
	password('hack').verifyAgainst(myuser.hash, myuser.salt, function(error, verified) {
		if(error)
			throw new Error('Something went wrong!');
		if(!verified) {
			console.log("Don't try! We got you!");
		} else {
			console.log("The secret is...");
		}
	});
})
