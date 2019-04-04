/**
 * Copyright 2018 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

'use strict';
const Promise = require('bluebird');
const eol = require('eol');
const sinon = require('sinon');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised');
const rewire = require('rewire');

const CertificateManagerWallet = rewire('../../../lib/impl/wallet/certificatemanagerwallet');
const X509WalletMixin = require('../../../lib/impl/wallet/x509walletmixin');
const api = require('fabric-client/lib/api.js');

const should = chai.should();
chai.use(chaiAsPromised);

// to mock out iam-token-manager calls and request-promise calls to certificate manager
const itm = CertificateManagerWallet.__get__('itm');
const rp = CertificateManagerWallet.__get__('rp');
const CertificateManagerKVS = CertificateManagerWallet.__get__('CertificateManagerKVS');

describe('CertificateManagerWallet', () => {
	const cert = `-----BEGIN CERTIFICATE-----
MIICfzCCAiWgAwIBAgIUNAqZVk9s5/HR7k30feNp8DrYbK4wCgYIKoZIzj0EAwIw
cDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNh
biBGcmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xGTAXBgNVBAMT
EG9yZzEuZXhhbXBsZS5jb20wHhcNMTgwMjI2MjAwOTAwWhcNMTkwMjI2MjAxNDAw
WjBdMQswCQYDVQQGEwJVUzEXMBUGA1UECBMOTm9ydGggQ2Fyb2xpbmExFDASBgNV
BAoTC0h5cGVybGVkZ2VyMQ8wDQYDVQQLEwZjbGllbnQxDjAMBgNVBAMTBWFkbWlu
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEz05miTKv6Vz+qhc5362WIZ44fs/H
X5m9zDOifle5HIjt4Usj+TiUgT1hpbI8UI9pueWhbrZpZXlX6+mImi52HaOBrzCB
rDAOBgNVHQ8BAf8EBAMCA6gwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMC
MAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFPnxMtT6jgYsMAgI38ponGs8sgbqMCsG
A1UdIwQkMCKAIKItrzVrKqtXkupT419m/M7x1/GqKzorktv7+WpEjqJqMCEGA1Ud
EQQaMBiCFnBlZXIwLm9yZzEuZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIh
AM1JowZMshCRs6dnOfRmUHV7399KnNvs5QoNw93cuQuAAiBtBEGh1Xt50tZjDcYN
j+yx4IraL4JvMrCHbR5/R+Xo1Q==
-----END CERTIFICATE-----`;
	const key = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgbTXpl4NGXuPtSC/V
PTVNGVBgVv8pZ6kGktVcnQD0KiKhRANCAATPTmaJMq/pXP6qFznfrZYhnjh+z8df
mb3MM6J+V7kciO3hSyP5OJSBPWGlsjxQj2m55aFutmlleVfr6YiaLnYd
-----END PRIVATE KEY-----
`;

	const certDescriptionInCM = JSON.stringify({
		name: 'identity1', mspid: 'mspOrg1', roles: null, affiliation: '', enrollmentSecret: '',
		enrollment: {
			signingIdentity: '489308420984923048230',
			identity: {}
		}
	});

	let testwallet;
	let sandbox;
	let FakeLogger;

	beforeEach(() => {
		sandbox = sinon.createSandbox();
		FakeLogger = {
			error: () => {},
			debug: () => {}
		};
		sandbox.stub(FakeLogger);
		CertificateManagerWallet.__set__('logger', FakeLogger);
		sandbox.stub(itm.prototype, 'getAuthHeader').callsFake(() => 'tokenheader'); // mock out call to iam token manager

		testwallet = new CertificateManagerWallet({url: 'http://someurl', apiKey: 'testapikey', instanceId: 'testinstanceId'});
	});

	afterEach(() => {
		sandbox.restore();
	});

	describe('#constructor', () => {
		it('should throw an error if no options given', () => {
			(() => {
				new CertificateManagerWallet();
			}).should.throw(/Must provide the IBM Certificate Manager url to store membership data./);
		});

		it('should throw an error if no url given', () => {
			(() => {
				new CertificateManagerWallet({});
			}).should.throw(/Must provide the IBM Certificate Manager url to store membership data./);
		});

		it('should default to X509 wallet mixin', () => {
			testwallet.walletMixin.should.be.an.instanceof(X509WalletMixin);
		});

		it('should accept a mixin parameter', () => {
			const wallet = new CertificateManagerWallet({url: 'http://someurl'}, 'my_mixin');
			sinon.assert.calledWith(FakeLogger.debug, 'inside constructor()');
			wallet.walletMixin.should.equal('my_mixin');
		});

		it('should create in memory cert objects', () => {
			const wallet = new CertificateManagerWallet({url: 'http://someurl'}, 'my_mixin');
			wallet.options.should.deep.equal({url: 'http://someurl', inMemoryCertDataToSet: {}, inMemoryCertDataToGet: {}});
		});
	});

	describe('#getStateStore', () => {
		it('should create a KV store and log that it was created', async() => {
			const kvs = await testwallet.getStateStore('test');
			kvs.should.be.an.instanceof(api.KeyValueStore);
			sinon.assert.calledWith(FakeLogger.debug, 'in getStateStore with label test');
		});
	});

	describe('#getCryptoSuite', () => {
		it('should set the cryptoSuite', async() => {
			const suite = await testwallet.getCryptoSuite('test');
			suite.should.be.an.instanceof(api.CryptoSuite);
			sinon.assert.calledWith(FakeLogger.debug, 'in getCryptoSuite with label test');
		});
	});

	describe('#exists', () => {
		it('should return true if identity exists', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity1',
						_id: 'identity1'
					}
				]
			})));

			const existence = await testwallet.exists('identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'in exists() with label identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'inside generateAuthTokenHeader() with apikey testapikey');
			sinon.assert.calledWith(FakeLogger.debug, 'inside getCertificateId');
			existence.should.equal(true);
		});

		it('should return false if identity is not found', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity2',
						_id: 'identity2'
					}
				]
			})));

			const existence = await testwallet.exists('identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'in exists() with label identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'inside generateAuthTokenHeader() with apikey testapikey');
			sinon.assert.calledWith(FakeLogger.debug, 'inside getCertificateId');
			existence.should.equal(false);
		});

		it('should handle an error connecting to certificate manager', async () => {
			// mock out call to iam token manager
			itm.prototype.getAuthHeader.restore();
			sandbox.stub(itm.prototype, 'getAuthHeader').returns(Promise.reject('error'));
			return testwallet.exists('test').should.be.rejectedWith(Error);
		});
	});

	describe('#import', () => {
		const identity1 = {
			certificate: cert,
			privateKey: key,
			mspId: 'mspOrg1'
		};

		it('should successfully import an identity', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'post').returns(Promise.resolve('success'));

			await testwallet.import('identity1', identity1);
			sinon.assert.calledWith(FakeLogger.debug, 'inside importCertificate');
			sinon.assert.calledWith(FakeLogger.debug, 'Sending request to IBM Certificate Manager...');
		});

		it('should handle error importing an identity to certificate manager', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'post').returns(Promise.reject('error'));

			return testwallet.import('identity1', identity1).should.be.rejectedWith(Error);
		});
	});

	describe('#export', () => {
		it('should successfully export an existing identity', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity1',
						_id: 'identity1'
					}
				],
				data: {
					priv_key: key,
					content: cert
				},
				description: certDescriptionInCM
			})));

			const identity = await testwallet.export('identity1');
			identity.type.should.equal('X509');
			identity.mspId.should.equal('mspOrg1');
			identity.certificate.should.equal(cert);
			eol.auto(identity.privateKey).should.equal(eol.auto(key)); // have to normalize eol chars
		});

		it('should return null when exporting an identity that does not exist', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity2',
						_id: 'identity2'
					}
				],
				data: {
					priv_key: key,
					content: cert
				},
				description: certDescriptionInCM
			})));

			const identity = await testwallet.export('identity1');
			should.equal(identity, null);
		});

		it('should handle an error connecting to certificate manager', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'get').returns(Promise.reject('error'));
			return testwallet.export('identity1').should.be.rejectedWith(Error);
		});
	});

	describe('#delete', () => {
		it('should delete an identity from the wallet if it exists', async () => {
			// mock out call to certificate manager for getting certificate id and deleting
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity1',
						_id: 'identity1'
					}
				]
			})));

			sandbox.stub(rp, 'delete').returns(Promise.resolve('ok'));

			const deleteTest = await testwallet.delete('identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'in delete() with label identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'inside generateAuthTokenHeader() with apikey testapikey');
			sinon.assert.calledWith(FakeLogger.debug, 'inside getCertificateId');
			sinon.assert.calledWith(FakeLogger.debug, 'inside deleteCertificate with certificateId: identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'deleted certificate successfully');
			deleteTest.should.equal(true);
		});

		it('should fail to delete an identity from the wallet that does not exist', async () => {
			// mock out call to certificate manager for getting certificate id and deleting
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity2',
						_id: 'identity2'
					}
				]
			})));

			const deleteTest = await testwallet.delete('identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'in delete() with label identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'inside generateAuthTokenHeader() with apikey testapikey');
			sinon.assert.calledWith(FakeLogger.debug, 'inside getCertificateId');
			sinon.assert.calledWith(FakeLogger.debug, 'identity identity1 not found');
			deleteTest.should.equal(false);
		});

		it('should fail to delete an identity if request to certificate manager fails', async () => {
			// mock out call to certificate manager for getting certificate id and deleting
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity1',
						_id: 'identity1'
					}
				]
			})));

			sandbox.stub(rp, 'delete').returns(Promise.reject('error'));

			const deleteTest = await testwallet.delete('identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'in delete() with label identity1');
			sinon.assert.calledWith(FakeLogger.debug, 'inside generateAuthTokenHeader() with apikey testapikey');
			sinon.assert.calledWith(FakeLogger.debug, 'inside deleteCertificate with certificateId: identity1');
			deleteTest.should.equal(false);
		});
	});

	describe('#list', () => {
		it('should list all identities in the wallet', async () => {
			// mock out call to certificate manager for getting list of certificates
			sandbox.stub(rp, 'get').returns(Promise.resolve(JSON.stringify({
				certificates: [
					{
						name: 'identity1',
						_id: 'identity1'
					}
				],
				data: {
					priv_key: key,
					content: cert
				},
				description: certDescriptionInCM
			})));

			const listOfCerts = await testwallet.list();
			listOfCerts.should.be.an.instanceof(Array);
			listOfCerts.length.should.equal(1);
			listOfCerts.should.deep.equal([{
				label: 'identity1',
				mspId: 'mspOrg1',
				identifier: '42b13cc85532f6c4b412ade462fa87dfd841603a3d30d4ca21d317d204c566c5'
			}]);
		});

		it('should throw error when request to certificate manager fails', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'get').returns(Promise.reject('error'));

			return testwallet.list().should.be.rejectedWith(Error);
		});
	});
});

describe('CertificateManagerKVS', () => {
	let certManagerStore;
	let sandbox;
	let FakeLogger;

	beforeEach(async () => {
		sandbox = sinon.createSandbox();
		FakeLogger = {
			error: () => {},
			debug: () => {}
		};
		sandbox.stub(FakeLogger);
		CertificateManagerWallet.__set__('logger', FakeLogger);

		const wallet = new CertificateManagerWallet({url: 'http://someurl', apiKey: 'testapikey', instanceId: 'testinstanceId'});
		certManagerStore = await wallet.getStateStore('test');
	});

	afterEach(() => {
		sandbox.restore();
	});

	describe('#constructor', () => {
		it('should throw an error if no options given', () => {
			(() => {
				new CertificateManagerKVS({});
			}).should.throw(/Must provide the IBM Certificate Manager url to store membership data./);
		});
	});

	describe('#getValue', () => {
		it('should simply log when it gets public key - this shouldn\'t happen', async () => {
			await certManagerStore.getValue('test-pub');
			sinon.assert.calledWith(FakeLogger.debug, 'Need to get the public key');
		});
	});

	describe('#getCertificate', () => {
		it('should throw error when request to certificate manager fails', async () => {
			// mock out call to certificate manager
			sandbox.stub(rp, 'get').returns(Promise.reject('error'));
			return certManagerStore.getCertificate('certId', 'authtoken').should.be.rejectedWith(Error);
		});
	});
});
