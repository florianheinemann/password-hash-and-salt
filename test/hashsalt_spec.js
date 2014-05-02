'use strict';

var expect = require('chai').expect;
var password = require('../index');

var splitHash = function(hash) {
	var opt = hash.split('$');
	if(opt.length !== 4)
		throw new Error('Hash expected to have four parts')
	return {
		algorithm: opt[0],
		iterations: opt[1],
		hash: opt[2],
		salt: opt[3]
	}
}

describe('Password hash and salt', function() {
	describe('Hash creation', function() {
		it('should not hash empty passwords', function (done) {
			password('').hash(function(error1, key1) {
				expect(error1).to.exist;
				expect(key1).to.not.exist;
				done();
			});
		});

		it('should return a key formatted as: alg$iterations$hash$salt', function (done) {
			password('secret').hash(function(error1, key1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				var split = splitHash(key1);
				expect(split.algorithm).to.equal('pbkdf2');
				expect(split.iterations).to.equal('10000');
				expect(split.hash.length).to.be.at.least(10);
				expect(split.salt.length).to.be.at.least(10);
				done();
			});
		});

		it('should create unique hashes', function (done) {
			password('password 1').hash(function(error1, key1) {
				password('password 2').hash(function(error2, key2) {
					expect(key1).not.to.be.null;
					expect(key2).not.to.be.null;
					expect(key1).to.not.equal(key2);
					expect(splitHash(key1).hash).to.not.equal(splitHash(key2).hash);
					done();
				})
			});
		});

		it('should create unique salts', function (done) {
			password('password 1').hash(function(error1, key1) {
				password('password 1').hash(function(error2, key2) {
					expect(key1).not.to.be.null;
					expect(key2).not.to.be.null;
					expect(splitHash(key1).salt).to.not.equal(splitHash(key2).salt);
					done();
				})
			});
		});

		it('should create same hash for same password and salt', function (done) {
			password('password 1').hash(function(error1, key1) {
				var salt1 = splitHash(key1).salt;
				password('password 1').hash(salt1, function(error2, key2) {
					expect(key1).to.exist;
					expect(salt1).to.exist;
					expect(key2).to.exist;
					expect(error1).to.not.exist;
					expect(error2).to.not.exist;

					expect(key1).to.equal(key2);

					done();
				})
			});
		});
	});

	describe('Hash verification', function() {
		it('should not verify empty passwords - 1', function (done) {
			password('password 1').hash(function(error1, key1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				password('password 1').verifyAgainst('', function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(false);
					done();
				});
			});
		});

		it('should not verify empty passwords - 2', function (done) {
			password('password 1').hash(function(error1, key1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				password('').verifyAgainst('password 1', function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(false);
					done();
				});
			});
		});
		
		it('should not verify with empty salt', function (done) {
			password('secret').verifyAgainst('pbkdf2$10000$5e45$', function(error2, validated) {
				expect(error2).to.exist;
				expect(validated).to.not.equal(true);
				done();
			});
		});
		
		it('should not verify with empty hash', function (done) {
			password('secret').verifyAgainst('pbkdf2$10000$$5e45', function(error2, validated) {
				expect(error2).to.exist;
				expect(validated).to.not.equal(true);
				done();
			});
		});
		
		it('should not verify with wrong or empty algorithm', function (done) {
			password('secret').verifyAgainst('$10000$5e45$5e45', function(error2, validated) {
				expect(error2).to.exist;
				expect(validated).to.not.equal(true);
				password('secret').verifyAgainst('new$10000$5e45$5e45', function(error2, validated) {
					expect(error2).to.exist;
					expect(validated).to.not.equal(true);
					done();
				});
			});
		});
		
		it('should not verify with wrong or empty iterations', function (done) {
			password('secret').verifyAgainst('pbkdf2$$5e45$5e45', function(error2, validated) {
				expect(error2).to.exist;
				expect(validated).to.not.equal(true);
				password('secret').verifyAgainst('pbkdf2$9999$5e45$5e45', function(error2, validated) {
					expect(error2).to.exist;
					expect(validated).to.not.equal(true);
					done();
				});
			});
		});
		
		it('should not verify with wrongly formatted hash - 1', function (done) {
			password('secret').verifyAgainst('random characters', function(error2, validated) {
				expect(error2).to.exist;
				expect(validated).to.not.equal(true);
				done();
			});
		});
		
		it('should not verify with wrongly formatted hash - 2', function (done) {
			password('secret').verifyAgainst('alg$1000$5e45$5e45$something', function(error2, validated) {
				expect(error2).to.exist;
				expect(validated).to.not.equal(true);
				done();
			});
		});

		it('should not verify wrong passwords', function (done) {
			password('secret').hash(function(error1, key1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				password('secret').verifyAgainst('pbkdf2$10000$5e45$5e45', function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(false);
					done();
				});
			});
		});

		it('should verify correct passwords', function (done) {
			password('secret').hash(function(error1, key1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				password('secret').verifyAgainst(key1, function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(true);
					done();
				});
			});
		});
	});
});