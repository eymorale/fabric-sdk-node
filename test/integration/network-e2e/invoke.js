/**
 * Copyright 2018 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// This is an end-to-end test that focuses on exercising all parts of the fabric APIs
// in a happy-path scenario
'use strict';

const tape = require('tape');
const _test = require('tape-promise').default;
const test = _test(tape);
const {Gateway, CouchDBWallet, InMemoryWallet, FileSystemWallet, X509WalletMixin, DefaultEventHandlerStrategies} = require('../../../fabric-network/index.js');
const sampleEventStrategy = require('./sample-transaction-event-handler');
const fs = require('fs-extra');
const os = require('os');
const path = require('path');
const rimraf = require('rimraf');

const e2eUtils = require('../e2e/e2eUtils.js');
const testUtils = require('../../unit/util');
const channelName = testUtils.NETWORK_END2END.channel;
const chaincodeId = testUtils.NETWORK_END2END.chaincodeId;

let fixtures = process.cwd() + '/test/fixtures';
let credPath = fixtures + '/channel/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com';
let cert = fs.readFileSync(credPath + '/signcerts/User1@org1.example.com-cert.pem').toString();
let key = fs.readFileSync(credPath + '/keystore/e4af7f90fa89b3e63116da5d278855cfb11e048397261844db89244549918731_sk').toString();
const inMemoryWallet = new InMemoryWallet();
let ccp = fs.readFileSync(fixtures + '/network.json');
const ccpDiscovery = fs.readFileSync(fixtures + '/network-discovery.json');

async function inMemoryIdentitySetup() {
	await inMemoryWallet.import('User1@org1.example.com', X509WalletMixin.createIdentity('Org1MSP', cert, key));
}

async function tlsSetup() {
	const tlsInfo = await e2eUtils.tlsEnroll('org1');
	await inMemoryWallet.import('tlsId', X509WalletMixin.createIdentity('org1', tlsInfo.certificate, tlsInfo.key));
}

async function createContract(t, gateway, gatewayOptions) {
	const profile = gatewayOptions.useDiscovery ? ccpDiscovery : ccp;
	await gateway.connect(JSON.parse(profile.toString()), gatewayOptions);
	t.pass('Connected to the gateway');

	const network = await gateway.getNetwork(channelName);
	t.pass('Initialized the network, ' + channelName);

	const contract = network.getContract(chaincodeId);
	t.pass('Got the contract');

	return contract;
}

async function getFirstEventHubForOrg(gateway, orgMSP) {
	const network = await gateway.getNetwork(channelName);
	const channel = network.getChannel();
	const orgPeer = channel.getPeersForOrg(orgMSP)[0];
	return channel.getChannelEventHub(orgPeer.getName());
}

test('\n\n***** Network End-to-end flow: import identity into wallet and configure tls *****\n\n', async (t) => {
	try {
		await inMemoryIdentitySetup();
		await tlsSetup();
		const exists = await inMemoryWallet.exists('User1@org1.example.com');
		if (exists) {
			t.pass('Successfully imported User1@org1.example.com into wallet');
		} else {
			t.fail('Failed to import User1@org1.example.com into wallet');
		}
	} catch (err) {
		t.fail('Failed to import identity into wallet and configure tls. ' + err.stack ? err.stack : err);
	}
	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and default event strategy with discovery *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			discovery: {
				asLocalHost: true
			}
		});

		const transaction = contract.createTransaction('move');
		const transactionId = transaction.getTransactionID().getTransactionID();

		// Obtain an event hub that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		const org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let eventFired = 0;

		// have to register for all transaction events (a new feature in 1.3) as
		// there is no way to know what the initial transaction id is
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				eventFired++;
			}
		}, () => {});

		const response = await transaction.submit('a', 'b', '100');

		t.true(org1EventHub.isconnected(), 'org1 event hub correctly connected');
		t.false(org2EventHub.isconnected(), 'org2 event hub correctly not connected');
		t.equal(eventFired, 1, 'single event for org1 correctly unblocked submitTransaction');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke multiple transactions to move money using in memory wallet and default event strategy *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			discovery: {
				enabled: false
			}
		});

		const transactions = new Array(3).fill('move').map((name) => contract.createTransaction(name));
		const transactionIds = transactions.map((tx) => tx.getTransactionID().getTransactionID());

		// Obtain an event hub that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		const org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let eventFired = 0;

		// have to register for all transaction events (a new feature in 1.3) as
		// there is no way to know what the initial transaction id is
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && transactionIds.includes(txId)) {
				eventFired++;
			}
		}, () => {});

		let response = await transactions[0].submit('a', 'b', '100');

		t.true(org1EventHub.isconnected(), 'org1 event hub correctly connected');
		t.false(org2EventHub.isconnected(), 'org2 event hub correctly not connected');
		t.equal(eventFired, 1, 'single event for org1 correctly unblocked submitTransaction');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked first transaction chaincode on channel');
		} else {
			t.fail('Unexpected response first from transaction chaincode: ' + response);
		}

		// second transaction for same connection
		response = await transactions[1].submit('a', 'b', '50');

		t.equal(eventFired, 2, 'single event for org1 correctly unblocked submitTransaction');

		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked second transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from second transaction chaincode: ' + response);
		}

		// third transaction for same connection
		response = await transactions[2].submit('a', 'b', '25');

		t.equal(eventFired, 3, 'single event for org1 correctly unblocked submitTransaction');

		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked third transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from third transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
	}


	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and MSPID_SCOPE_ALLFORTX event strategy *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: DefaultEventHandlerStrategies.MSPID_SCOPE_ALLFORTX
			},
			discovery: {
				enabled: false
			}
		});

		const transaction = contract.createTransaction('move');
		const transactionId = transaction.getTransactionID().getTransactionID();

		// Obtain an event hub that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		const org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let eventFired = 0;

		// have to register for all transaction events (a new feature in 1.3) as
		// there is no way to know what the initial transaction id is
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				eventFired++;
			}
		}, () => {});

		const response = await transaction.submit('a', 'b', '100');

		t.false(org2EventHub.isconnected(), 'org2 event hub correctly not connected');
		t.equal(eventFired, 1, 'single event for org1 correctly unblocked submitTransaction');
		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and MSPID_SCOPE_ANYFORTX event strategy *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;
	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: DefaultEventHandlerStrategies.MSPID_SCOPE_ANYFORTX
			},
			discovery: {
				enabled: false
			}
		});

		const transaction = contract.createTransaction('move');
		const transactionId = transaction.getTransactionID().getTransactionID();

		// Obtain an event hub that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		const org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let eventFired = 0;

		// have to register for all transaction events (a new feature in 1.3) as
		// there is no way to know what the initial transaction id is
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				eventFired++;
			}
		}, () => {});

		const response = await transaction.submit('a', 'b', '100');

		t.false(org2EventHub.isconnected(), 'org2 event hub correctly not connected');
		t.equal(eventFired, 1, 'single event for org1 correctly unblocked submitTransaction');
		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and NETWORK_SCOPE_ALLFORTX event strategy *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;
	let org2EventHub;

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: DefaultEventHandlerStrategies.NETWORK_SCOPE_ALLFORTX
			},
			discovery: {
				enabled: false
			}
		});

		const transaction = contract.createTransaction('move');
		const transactionId = transaction.getTransactionID().getTransactionID();

		// Obtain the event hubs that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let org1EventFired = 0;
		let org2EventFired = 0;
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org1EventFired++;
			}
		}, () => {});

		org2EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org2EventFired++;
			}
		}, () => {});

		const response = await transaction.submit('a', 'b', '100');

		const unblockCorrectly = (org1EventFired === 1) && (org2EventFired === 1);
		t.pass(`org1 events: ${org1EventFired}, org2 events: ${org2EventFired}`);
		t.true(unblockCorrectly, 'got single events at both org event hubs before submitTransaction was unblocked');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
		t.false(org2EventHub.isconnected(), 'org2 event hub correctly been disconnected');
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and NETWORK_SCOPE_ALLFORTX event strategy with discovery *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;
	let org2EventHub;

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: DefaultEventHandlerStrategies.NETWORK_SCOPE_ALLFORTX
			},
			discovery: {
				asLocalHost: true
			}
		});

		const transaction = contract.createTransaction('move');
		const transactionId = transaction.getTransactionID().getTransactionID();

		// Obtain the event hubs that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let org1EventFired = 0;
		let org2EventFired = 0;
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org1EventFired++;
			}
		}, () => {});

		org2EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org2EventFired++;
			}
		}, () => {});

		const response = await transaction.submit('a', 'b', '100');

		const unblockCorrectly = (org1EventFired === 1) && (org2EventFired === 1);
		t.pass(`org1 events: ${org1EventFired}, org2 events: ${org2EventFired}`);
		t.true(unblockCorrectly, 'got single events at both org event hubs before submitTransaction was unblocked');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
		t.false(org2EventHub.isconnected(), 'org2 event hub correctly been disconnected');
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and NETWORK_SCOPE_ANYFORTX event strategy *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;
	let org2EventHub;

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: DefaultEventHandlerStrategies.NETWORK_SCOPE_ANYFORTX
			},
			discovery: {
				enabled: false
			}
		});

		const transaction = contract.createTransaction('move');
		const transactionId = transaction.getTransactionID().getTransactionID();

		// Obtain the event hubs that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let org1EventFired = 0;
		let org2EventFired = 0;
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org1EventFired++;
			}
		}, () => {});

		org2EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org2EventFired++;
			}
		}, () => {});

		const response = await transaction.submit('a', 'b', '100');

		const unblockCorrectly = (org1EventFired === 1 && org2EventFired === 0) ||
								(org1EventFired === 0 && org2EventFired === 1)
								// || (org1EventFired === 1 && org2EventFired === 1) hopefully this doesn't have to be included due to timing
								;

		t.pass(`org1 events: ${org1EventFired}, org2 events: ${org2EventFired}`);
		t.true(unblockCorrectly, 'single event received by one of the event hubs caused submitTransaction to unblock, before other event received');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		// remove the disconnects once gateway disconnect cleans up event hubs
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
		t.false(org2EventHub.isconnected(), 'org2 event hub correctly been disconnected');
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and NETWORK_SCOPE_ANYFORTX event strategy with discovery *****\n\n', async (t) => {
	const gateway = new Gateway();
	let org1EventHub;
	let org2EventHub;

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: DefaultEventHandlerStrategies.NETWORK_SCOPE_ANYFORTX
			},
			discovery: {
				asLocalHost: true
			}
		});

		const transaction = contract.createTransaction('move');
		const transactionId = transaction.getTransactionID().getTransactionID();

		// Obtain the event hubs that that will be used by the underlying implementation
		org1EventHub = await getFirstEventHubForOrg(gateway, 'Org1MSP');
		org2EventHub = await getFirstEventHubForOrg(gateway, 'Org2MSP');

		let org1EventFired = 0;
		let org2EventFired = 0;
		org1EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org1EventFired++;
			}
		}, () => {});

		org2EventHub.registerTxEvent('all', (txId, code) => {
			if (code === 'VALID' && txId === transactionId) {
				org2EventFired++;
			}
		}, () => {});

		const response = await transaction.submit('a', 'b', '100');

		const unblockCorrectly = (org1EventFired === 1 && org2EventFired === 0) ||
			(org1EventFired === 0 && org2EventFired === 1)
			// || (org1EventFired === 1 && org2EventFired === 1) hopefully this doesn't have to be included due to timing
		;

		t.pass(`org1 events: ${org1EventFired}, org2 events: ${org2EventFired}`);
		t.true(unblockCorrectly, 'single event received by one of the event hubs caused submitTransaction to unblock, before other event received');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		// remove the disconnects once gateway disconnect cleans up event hubs
		gateway.disconnect();
		t.false(org1EventHub.isconnected(), 'org1 event hub correctly been disconnected');
		t.false(org2EventHub.isconnected(), 'org2 event hub correctly been disconnected');
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and plug-in event strategy *****\n\n', async (t) => {
	const gateway = new Gateway();

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: sampleEventStrategy
			},
			discovery: {
				enabled: false
			}
		});

		const response = await contract.submitTransaction('move', 'a', 'b', '100');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction with transient data *****\n\n', async (t) => {
	const gateway = new Gateway();

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			discovery: {
				enabled: false
			}
		});

		const transaction = contract.createTransaction('getTransient');
		const transientMap = {
			key1: Buffer.from('value1'),
			key2: Buffer.from('value2')
		};
		const response = await transaction.setTransient(transientMap).submit();
		t.pass('Got response: ' + response.toString('utf8'));
		const result = JSON.parse(response.toString('utf8'));

		let success = true;

		if (Object.keys(transientMap).length !== Object.keys(result).length) {
			success = false;
		}

		Object.entries(transientMap).forEach((entry) => {
			key = entry[0];
			const value = entry[1].toString();
			if (value !== result[key]) {
				t.fail(`Expected ${key} to be ${value} but was ${result[key]}`);
				success = false;
			}
		});

		if (success) {
			t.pass('Got expected transaction response');
		} else {
			t.fail('Unexpected transaction response: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction with empty string response *****\n\n', async (t) => {
	const gateway = new Gateway();

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			discovery: {
				enabled: false
			}
		});

		const response = await contract.submitTransaction('echo', '');

		if (response && response.toString('utf8') === '') {
			t.pass('Got expected transaction response');
		} else {
			t.fail('Unexpected transaction response: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: handle transaction error *****\n\n', async (t) => {
	const gateway = new Gateway();

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			discovery: {
				enabled: false
			}
		});

		const response = await contract.submitTransaction('throwError', 'a', 'b', '100');
		t.fail('Transaction "throwError" should have thrown an error.  Got response: ' + response.toString());
	} catch (expectedErr) {
		if (expectedErr.message.includes('throwError: an error occurred')) {
			t.pass('Successfully handled invocation errors');
		} else {
			t.fail('Unexpected exception: ' + expectedErr.message);
		}
	} finally {
		gateway.disconnect();
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in file system wallet *****\n\n', async (t) => {
	const tmpdir = path.join(os.tmpdir(), 'integration-network-test987');
	const gateway = new Gateway();

	try {
		// define the identity to use
		fixtures = process.cwd() + '/test/fixtures';
		credPath = fixtures + '/channel/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com';
		cert = fs.readFileSync(credPath + '/signcerts/User1@org1.example.com-cert.pem').toString();
		key = fs.readFileSync(credPath + '/keystore/e4af7f90fa89b3e63116da5d278855cfb11e048397261844db89244549918731_sk').toString();
		const identityLabel = 'User1@org1.example.com';

		const fileSystemWallet = new FileSystemWallet(tmpdir);

		// prep wallet and test it at the same time
		await fileSystemWallet.import(identityLabel, X509WalletMixin.createIdentity('Org1MSP', cert, key));
		const exists = await fileSystemWallet.exists(identityLabel);
		t.ok(exists, 'Successfully imported User1@org1.example.com into wallet');
		const tlsInfo = await e2eUtils.tlsEnroll('org1');

		await fileSystemWallet.import('tlsId', X509WalletMixin.createIdentity('org1', tlsInfo.certificate, tlsInfo.key));

		ccp = fs.readFileSync(fixtures + '/network.json');
		await gateway.connect(JSON.parse(ccp.toString()), {
			wallet: fileSystemWallet,
			identity: identityLabel,
			clientTlsIdentity: 'tlsId',
			discovery: {
				enabled: false
			}
		});

		t.pass('Connected to the gateway');

		const network = await gateway.getNetwork(channelName);

		t.pass('Initialized the channel, ' + channelName);

		const contract = await network.getContract(chaincodeId);

		t.pass('Got the contract, about to submit "move" transaction');

		let response = await contract.submitTransaction('move', 'a', 'b', '100');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}

		try {
			response = await contract.submitTransaction('throwError', 'a', 'b', '100');
			t.fail('Transaction "throwError" should have thrown an error.  Got response: ' + response.toString());
		} catch (expectedErr) {
			if (expectedErr.message.includes('throwError: an error occurred')) {
				t.pass('Successfully handled invocation errors');
			} else {
				t.fail('Unexpected exception: ' + expectedErr.message);
			}
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		// delete the file system wallet.
		const rimRafPromise = new Promise((resolve) => {
			rimraf(tmpdir, (err) => {
				if (err) {
					// eslint-disable-next-line no-console
					console.log(`failed to delete ${tmpdir}, error was ${err}`);
					resolve();
				}
				resolve();
			});
		});
		await rimRafPromise;
		gateway.disconnect();
	}

	t.end();
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using CouchDB wallet *****\n\n', async (t) => {
	const gateway = new Gateway();
	try {
		fixtures = process.cwd() + '/test/fixtures';
		credPath = fixtures + '/channel/crypto-config/peerOrganizations/org1.example.com/users/User1@org1.example.com';
		cert = fs.readFileSync(credPath + '/signcerts/User1@org1.example.com-cert.pem').toString();
		key = fs.readFileSync(credPath + '/keystore/e4af7f90fa89b3e63116da5d278855cfb11e048397261844db89244549918731_sk').toString();
		const identityLabel = 'user1-org1_example_com';

		const couchDBWallet = new CouchDBWallet({url: 'http://localhost:5984'});
		await couchDBWallet.import(identityLabel, X509WalletMixin.createIdentity('Org1MSP', cert, key));
		const exists = await couchDBWallet.exists(identityLabel);
		t.ok(exists, 'Successfully imported User1@org1.example.com into wallet');
		const tlsInfo = await e2eUtils.tlsEnroll('org1');

		await couchDBWallet.import('tls_id', X509WalletMixin.createIdentity('org1', tlsInfo.certificate, tlsInfo.key));

		ccp = fs.readFileSync(fixtures + '/network.json');
		await gateway.connect(JSON.parse(ccp.toString()), {
			wallet: couchDBWallet,
			identity: identityLabel,
			clientTlsIdentity: 'tls_id',
			discovery: {
				enabled: false
			}
		});

		t.pass('Connected to the gateway');

		const network = await gateway.getNetwork(channelName);

		t.pass('Initialized the channel, ' + channelName);

		const contract = await network.getContract(chaincodeId);

		t.pass('Got the contract, about to submit "move" transaction');

		let response = await contract.submitTransaction('move', 'a', 'b', '100');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}

		try {
			response = await contract.submitTransaction('throwError', 'a', 'b', '100');
			t.fail('Transaction "throwError" should have thrown an error.  Got response: ' + response.toString());
		} catch (expectedErr) {
			if (expectedErr.message.includes('throwError: an error occurred')) {
				t.pass('Successfully handled invocation errors');
			} else {
				t.fail('Unexpected exception: ' + expectedErr.message);
			}
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
	}
});

test('\n\n***** Network End-to-end flow: invoke transaction to move money using in memory wallet and no event strategy *****\n\n', async (t) => {
	const gateway = new Gateway();

	try {

		const contract = await createContract(t, gateway, {
			wallet: inMemoryWallet,
			identity: 'User1@org1.example.com',
			clientTlsIdentity: 'tlsId',
			eventHandlerOptions: {
				strategy: null
			},
			discovery: {
				enabled: false
			}
		});

		const response = await contract.submitTransaction('move', 'a', 'b', '100');

		const expectedResult = 'move succeed';
		if (response.toString() === expectedResult) {
			t.pass('Successfully invoked transaction chaincode on channel');
		} else {
			t.fail('Unexpected response from transaction chaincode: ' + response);
		}
	} catch (err) {
		t.fail('Failed to invoke transaction chaincode on channel. ' + err.stack ? err.stack : err);
	} finally {
		gateway.disconnect();
	}

	t.end();
});
