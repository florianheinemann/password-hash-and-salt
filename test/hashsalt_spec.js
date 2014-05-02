'use strict';

var expect = require('chai').expect;
var password = require('../index');

describe('Password hash and salt', function() {
	describe('Hash creation', function() {
		it('should not hash empty passwords', function (done) {
			password('').hash(function(error1, key1, salt1) {
				expect(error1).to.exist;
				expect(key1).to.not.exist;
				expect(salt1).to.not.exist;
				done();
			});
		});

		it('should create unique hashes', function (done) {
			password('password 1').hash(function(error1, key1, salt1) {
				password('password 2').hash(function(error2, key2, salt2) {
					expect(key1).not.to.be.null;
					expect(key2).not.to.be.null;
					expect(key1).to.not.deep.equal(key2);
					done();
				})
			});
		});

		it('should create unique salts', function (done) {
			password('password 1').hash(function(error1, key1, salt1) {
				password('password 1').hash(function(error2, key2, salt2) {
					expect(salt1).not.to.be.null;
					expect(salt2).not.to.be.null;
					expect(salt1).to.not.deep.equal(salt2);
					done();
				})
			});
		});

		it('should create same hash for same password and salt', function (done) {
			password('password 1').hash(function(error1, key1, salt1) {
				password('password 1').hash(salt1, function(error2, key2, salt2) {
					expect(key1).not.to.be.null;
					expect(salt1).not.to.be.null;

					expect(key1).to.deep.equal(key2);
					expect(salt1).to.deep.equal(salt2);

					done();
				})
			});
		});
	});

	describe('Hash verification', function() {
		it('should not verify empty passwords - 1', function (done) {
			password('password 1').hash(function(error1, key1, salt1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				expect(salt1).to.exist;
				password('password 1').verifyAgainst('', salt1, function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(false);
					done();
				});
			});
		});

		it('should not verify empty passwords - 2', function (done) {
			password('password 1').hash(function(error1, key1, salt1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				expect(salt1).to.exist;
				password('').verifyAgainst('password 1', salt1, function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(false);
					done();
				});
			});
		});
		
		it('should not verify with empty salt', function (done) {
			password('secret').hash(function(error1, key1, salt1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				expect(salt1).to.exist;
				password('secret').verifyAgainst('secret', '', function(error2, validated) {
					expect(error2).to.exist;
					expect(validated).to.not.equal(true);
					done();
				});
			});
		});

		it('should not verify wrong passwords - 1', function (done) {
			password('secret').hash(function(error1, key1, salt1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				expect(salt1).to.exist;
				password('secret').verifyAgainst('wrongsecret', salt1, function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(false);
					done();
				});
			});
		});

		it('should not verify wrong passwords - 2', function (done) {
			password('secret').hash(function(error1, key1, salt1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				expect(salt1).to.exist;
				password('wrongsecret').verifyAgainst('secret', salt1, function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(false);
					done();
				});
			});
		});

		it('should verify correct passwords', function (done) {
			password('secret').hash(function(error1, key1, salt1) {
				expect(error1).to.not.exist;
				expect(key1).to.exist;
				expect(salt1).to.exist;
				password('secret').verifyAgainst(key1, salt1, function(error2, validated) {
					expect(error2).to.not.exist;
					expect(validated).to.equal(true);
					done();
				});
			});
		});
	});
});