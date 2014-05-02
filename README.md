password-hash-and-salt
======================

This module provides straight-forward password hashing for node.js applications using default settings considered to be safe.

### Usage

First, install the module:

`$ npm install password-hash-and-salt --save`

Afterwards, usage is simple as shown in the following example:
```javascript
var password = require('password-hash-and-salt');

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

```

### Crypto
password-hash-and-salt uses node.js' internal crypto module. Hashes are generated with pbkdf2 using 10,000 iterations.

### License

[MIT License](http://opensource.org/licenses/MIT)

### Author
Florian Heinemann [http://twitter.com/florian__h/](http://twitter.com/florian__h/)
