password-hash-and-salt
======================

This module provides straight-forward password hashing for node.js applications using default settings considered to be safe.

### Usage

First, install the module:

`$ npm install password-hash-and-salt --save`

Afterwards, usage is as simple as shown in the following example:
```javascript
var password = require('password-hash-and-salt');

var myuser = [];

// Creating hash and salt
password('mysecret').hash(function(error, hash) {
	if(error)
		throw new Error('Something went wrong!');

	// Store hash (incl. algorithm, iterations, and salt)
	myuser.hash = hash;

	// Verifying a hash
	password('hack').verifyAgainst(myuser.hash, function(error, verified) {
		if(error)
			throw new Error('Something went wrong!');
		if(!verified) {
			console.log("Don't try! We got you!");
		} else {
			console.log("The secret is...");
		}
	});
})

```

### Crypto
password-hash-and-salt uses node.js' internal crypto module. Hashes are generated with pbkdf2 using 10,000 iterations.

### Created hash
The created hash is of 270 characters length and is of the following format:
`pbkdf2$10000$hash$salt`

This allows for future upgrades of the algorithm and/or increased number of iterations in future version. It also simplifies storage as no dedicated database field for the salt is required.

### Credits and License
express-sslify is licensed under the MIT license. If you'd like to be informed about new projects follow   [@TheSumOfAll](http://twitter.com/TheSumOfAll/).

Copyright (c) 2013-2014 Florian Heinemann
