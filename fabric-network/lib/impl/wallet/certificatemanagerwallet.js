/**
 * Copyright 2018 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
'use strict';

const rp = require('request-promise');
const itm = require('@ibm-functions/iam-token-manager');
const Client = require('fabric-client');
const api = require('fabric-client/lib/api');

const BaseWallet = require('./basewallet');
const logger = require('../../logger').getLogger('CertificateManagerWallet');

/**
 * @typedef {object} CertificateManagerWallet~CertificateManagerWalletOptions
 * @memberof module:fabric-network
 * @property {string} url CertificateManager URL
 */

/**
 * This class defines an implementation of an Identity wallet that persists
 * to an IBM Certificate Manager
 * @memberof module:fabric-network
 * @implements {module:fabric-network.Wallet}
 */
class CertificateManagerWallet extends BaseWallet {
	/**
	 * Creates an instance of the CertificateManagerWallet
	 * @param {module:fabric-network.CertificateManagerWallet~CertificateManagerWalletOptions} options
	 * @param {WalletMixin} [mixin] Optionally provide an alternative wallet mixin.
	 * Defaults to [X509WalletMixin]{@link module:fabric-network.X509WalletMixin}.
	 */
	constructor(options, mixin) {
		super(mixin);
		logger.debug('inside constructor()');

		if (!options || !options.url) {
			throw new Error('Must provide the IBM Certificate Manager url to store membership data.');
		}

		this.options = options;

		/**
		 * IBM Certificate Manager stores certificate and private key together
		 * In order to follow the fabric-network's wallet implementation contract of
		 * setting and getting these 2 resources separately, we have to maintain an
		 * in memory variable per wallet instance for setting and getting these resources.
		 * More explained in CertificateManagerKVS's getValue and setValue
		 */
		this.options.inMemoryCertDataToSet = {};
		this.options.inMemoryCertDataToGet = {};
	}

	async getStateStore(label) {
		logger.debug(`in getStateStore with label ${label}`);
		return await new CertificateManagerKVS(this.options);
	}

	async getCryptoSuite(label) {
		logger.debug(`in getCryptoSuite with label ${label}`);
		const cryptoSuite = Client.newCryptoSuite();
		cryptoSuite.setCryptoKeyStore(Client.newCryptoKeyStore(CertificateManagerKVS, this.options));
		return cryptoSuite;
	}

	/**
	 * @private
	 */
	async exists(label) {
		logger.debug(`in exists() with label ${label}`);
		try {
			label = this.normalizeLabel(label);
			const kvs = await this.getStateStore();
			return await kvs.exists(label);
		} catch (err) {
			throw new Error(err.message);
		}
	}

	async delete(label) {
		logger.debug(`in delete() with label ${label}`);
		label = this.normalizeLabel(label);
		const kvs = await this.getStateStore();
		return kvs.delete(label);
	}

	async getAllLabels() {
		logger.debug('in getAllLabels()');
		try {
			const kvs = await this.getStateStore();
			return await kvs.getAllLabels();
		} catch (err) {
			throw new Error(err.message);
		}
	}
}

/**
 * This is a database implementation of the [KeyValueStore]{@link module:api.KeyValueStore} API.
 * It uses a remote IBM Certificate Manager database instance to store the keys.
 *
 * @class
 * @extends module:api.KeyValueStore
 */
class CertificateManagerKVS extends api.KeyValueStore {

	/**
	 * constructor
	 *
	 * @param {CertificateManagerOpts} options Settings used to connect to a Certificate Manager instance
	 */
	constructor(options) {
		logger.debug(`CertificateManagerKVS constructor: ${options}`);

		if (!options || !options.url) {
			throw new Error('Must provide the IBM Certificate Manager url to store membership data.');
		}

		super();
		this.options = options;

		// in memory identity needs to be per wallet instance
		this.inMemoryIdentityToSet = options.inMemoryCertDataToSet;
		this.inMemoryIdentityToGet = options.inMemoryCertDataToGet;
		return Promise.resolve(this);
	}

	/**
	 * Need to make a single request to IBM Certificate Manager to get certificate
	 * and its private key. Store the result in the in memory object since the fabric-network
	 * wallet implementation requests these resources separately
	 *
	 * Public key isn't requested so for now, don't do anything
	 */
	async getValue(name) {
		logger.debug(`getValue, name = ${name}`);

		// if private key is requested, return it from the in memory object
		// if identity name i.e. app1, make request to Certificate Manager then store results in the in memory object
		// identity name will be requested first followed by the private key
		if (name.includes('-priv')) {
			return this.inMemoryIdentityToGet.priv;
		} else if (name.includes('-pub')) {
			logger.debug('Need to get the public key');
		} else {
			try {
				// generate auth token header, get certificate id based on identity name and then get contents
				const myAuthTokenHeader = await this.generateAuthTokenHeader(this.options.apiKey);
				const certificateId = await this.getCertificateId(name, myAuthTokenHeader);
				if (!certificateId) {
					return null;
				}

				const identity = await this.getCertificate(certificateId, myAuthTokenHeader);
				logger.debug(`identity: ${JSON.stringify(identity)}`);

				// parse out data to conform to proper wallet response
				this.inMemoryIdentityToGet.priv = identity.data.priv_key; // store the private key for when it's requested
				this.inMemoryIdentityToGet.metadata = JSON.parse(identity.description);
				// add the cert contents back to the metadata, since that is the format it was originally in and what the SDK expects
				this.inMemoryIdentityToGet.metadata.enrollment.identity.certificate = identity.data.content;

				// return stringified metadata object that includes the certificate
				return JSON.stringify(this.inMemoryIdentityToGet.metadata);
			} catch (err) {
				throw new Error(err.message);
			}
		}
	}

	/**
	 * IBM Certificate Manager requires storing the certificate and private key together in the same request. This does not conform to
	 * the fabric-network's wallet implementation, where private key and certificate are stored seperately with their own individual keys.
	 * In order to follow the wallet's contract, we must collect all of the individual pieces and store them in memory. Once we have everything,
	 * we can make the request to Certificate Manager to import the identity
	 */
	async setValue(name, value) {
		logger.debug(`setValue, name = ${name}`);
		logger.debug(`this.inMemoryIdentityToSet: ${JSON.stringify(this.inMemoryIdentityToSet)}`);

		// store private key, public key, and metadata with cert in memory for use in request to Certificate Manager
		// when everything is collected
		if (name.includes('-priv')) {
			this.inMemoryIdentityToSet.priv = value;
		} else if (name.includes('-pub')) {
			this.inMemoryIdentityToSet.pub = value;
		} else {
			this.inMemoryIdentityToSet.metadata = JSON.parse(value);
		}

		// Everything needed for the request to Certificate Manager has been collected - import certificate
		if (this.inMemoryIdentityToSet.priv && this.inMemoryIdentityToSet.pub && this.inMemoryIdentityToSet.metadata) {
			logger.debug(`All data is set - importing certificate: ${JSON.stringify(this.inMemoryIdentityToSet)}`);
			try {
				const myAuthTokenHeader = await this.generateAuthTokenHeader(this.options.apiKey);

				// take out certificate and identity name from metadata, stringify the remaining metadata to be stored in description
				// const { certificate, ...remaining } = this.inMemoryIdentityToSet.metadata.enrollment.identity;
				const certificate = this.inMemoryIdentityToSet.metadata.enrollment.identity.certificate;
				delete this.inMemoryIdentityToSet.metadata.enrollment.identity.certificate;
				const identityName = this.inMemoryIdentityToSet.metadata.name;
				const description = JSON.stringify(this.inMemoryIdentityToSet.metadata);
				const result = await this.importCertificate(myAuthTokenHeader, identityName, certificate,
					this.inMemoryIdentityToSet.priv, description);

				// reset in memory identity data
				this.resetInMemoryIdentity(this.inMemoryIdentityToSet);

				return result;
			} catch (err) {
				// reset in memory identity data
				this.resetInMemoryIdentity(this.inMemoryIdentityToSet);
				throw new Error(err.message);
			}
		}

		return value;
	}

	/**
	 * Make request out to Certificate Manager to search for specified identity
	 */
	async exists(label) {
		logger.debug(`inside exists() with label ${label}`);
		try {
			const myAuthTokenHeader = await this.generateAuthTokenHeader(this.options.apiKey);
			const certificateId = await this.getCertificateId(label, myAuthTokenHeader);
			logger.debug(`certificateId: ${certificateId}`);
			if (!certificateId) {
				logger.debug('certificateId not found');
				return false;
			}

			logger.debug('certificateId found');
			return true;
		} catch (err) {
			throw new Error(err.message);
		}
	}

	/**
	 * Make request out to Certificate Manager to delete the specified identity
	 */
	async delete(label) {
		logger.debug(`inside delete() with label ${label}`);
		try {
			const myAuthTokenHeader = await this.generateAuthTokenHeader(this.options.apiKey);
			const certificateId = await this.getCertificateId(label, myAuthTokenHeader);
			if (!certificateId) {
				logger.debug(`identity ${label} not found`);
				return false;
			}

			await this.deleteCertificate(certificateId, myAuthTokenHeader);

			logger.debug('deleted certificate successfully');
			return true;
		} catch (err) {
			logger.error(err.message);
			return false;
		}
	}

	/**
	 * Make request out to Certificate Manager to get list of identities
	 */
	async getAllLabels() {
		logger.debug('inside getAllLabels()');
		try {
			const myAuthTokenHeader = await this.generateAuthTokenHeader(this.options.apiKey);
			const certificateIds = await this.getCertificateIds(myAuthTokenHeader);
			logger.debug(`certificateIds: ${certificateIds}`);
			return certificateIds;
		} catch (err) {
			throw new Error(err.message);
		}
	}

	/**
	 * Certificate Manager helper functions
	 */

	// clear contents of the in memory object
	resetInMemoryIdentity(inMemoryIdentity) {
		for (const [key] of Object.entries(inMemoryIdentity)) {
			inMemoryIdentity[key] = '';
		}
	}

	// generate an auth token header based on apikey
	async generateAuthTokenHeader(apiKey) {
		logger.debug(`inside generateAuthTokenHeader() with apikey ${apiKey}`);
		try {
			const m = new itm({
				'iamApikey': apiKey
			});

			const token = await m.getAuthHeader(); // returns Bearer HTTP Authorization header including the token
			return token;
		} catch (err) {
			throw new Error(err.message);
		}
	}

	// import a certificate to Certificate Manager
	async importCertificate(authTokenHeader, identityName, certificate, privateKey, description) {
		logger.debug('inside importCertificate');

		const instanceId = encodeURIComponent(this.options.instanceId);
		const importURL = `${this.options.url}/api/v3/${instanceId}/certificates/import`;

		const reqOptions = {
			headers: {
				'Authorization': authTokenHeader
			},
			body: {
				name: identityName,
				description: description,
				data: {
					content: certificate,
					priv_key: privateKey,
				}
			},
			json: true
		};

		logger.debug(`request options: ${JSON.stringify(reqOptions)}`);

		try {
			logger.debug('Sending request to IBM Certificate Manager...');
			const result = await rp.post(importURL, reqOptions);
			logger.debug(JSON.stringify(result));

			return result;
		} catch (err) {
			throw new Error(err.message);
		}
	}

	// delete a certificate from Certificate Manager
	async deleteCertificate(certificateId, authTokenHeader) {
		logger.debug(`inside deleteCertificate with certificateId: ${certificateId}`);

		try {
			const encodedCertId = encodeURIComponent(certificateId);
			const certURL = `${this.options.url}/api/v2/certificate/${encodedCertId}`;

			const reqOptions = {
				headers: {
					'Authorization': authTokenHeader
				}
			};

			logger.debug('Sending request to IBM Certificate Manager...');
			const result = await rp.delete(certURL, reqOptions);
			logger.debug(result);
		} catch (err) {
			throw new Error(err.message);
		}
	}

	// get all certificates from repository and return their ids
	async getCertificateIds(authTokenHeader) {
		logger.debug('inside getCertificateIds');

		try {
			const instanceId = encodeURIComponent(this.options.instanceId);
			const certsURL = `${this.options.url}/api/v3/${instanceId}/certificates`;

			const reqOptions = {
				headers: {
					'Authorization': authTokenHeader
				},
				qs: {
					order: 'name',
					page_number: 0,
					page_size: 100
				}
			};

			logger.debug('Sending request to IBM Certificate Manager...');
			let result = await rp.get(certsURL, reqOptions);
			result = JSON.parse(result);
			logger.debug(JSON.stringify(result.certificates));
			logger.debug('Iterating over certificates');

			const certificateIds = result.certificates.map(({name}) => {
				return name;
			});

			return certificateIds;
		} catch (err) {
			throw new Error(err.message);
		}
	}

	// get all certificates from repository and then retrives the certificate id based on the label
	async getCertificateId(label, authTokenHeader) {
		logger.debug('inside getCertificateId');

		try {
			const instanceId = encodeURIComponent(this.options.instanceId);
			const certsURL = `${this.options.url}/api/v3/${instanceId}/certificates`;

			const reqOptions = {
				headers: {
					'Authorization': authTokenHeader
				},
				qs: {
					order: 'name',
					page_number: 0,
					page_size: 100
				}
			};

			logger.debug('Sending request to IBM Certificate Manager...');
			let result = await rp.get(certsURL, reqOptions);
			result = JSON.parse(result);
			logger.debug(JSON.stringify(result.certificates));
			logger.debug('Iterating over certificates');
			for (const certificate of result.certificates) {
				if (certificate.name === label) {
					logger.debug(`Found cert: ${certificate._id}`);
					return certificate._id;
				}
			}

			return null;
		} catch (err) {
			throw new Error(err.message);
		}
	}

	// get certificate by id
	async getCertificate(certificateId, authTokenHeader) {
		logger.debug('inside getCertificate');

		try {
			const encodedCertId = encodeURIComponent(certificateId);
			const certURL = `${this.options.url}/api/v2/certificate/${encodedCertId}`;

			const reqOptions = {
				headers: {
					'Authorization': authTokenHeader
				}
			};

			logger.debug('Sending request to IBM Certificate Manager...');
			const result = await rp.get(certURL, reqOptions);
			return JSON.parse(result);
		} catch (err) {
			throw new Error(err.message);
		}
	}
}

module.exports = CertificateManagerWallet;
