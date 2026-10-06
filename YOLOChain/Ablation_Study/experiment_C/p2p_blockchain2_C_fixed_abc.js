#!/usr/bin/env node

'use strict';

/*****************************************************************
 * YOLOChain
 * Experiment C
 *
 * YOLOv8
 *   |
 * MQTT QoS 1
 *   |
 * Validator 1
 *   |
 * Plain TCP P2P
 *   |
 * PBFT-style
 *   |
 * Local Blockchain
 *
 * PQC       = OFF
 * KEM       = OFF
 * AES       = OFF
 * Signatures= OFF
 *
 * N = 4
 * F = 1
 * QUORUM = 3
 *
 * IMPORTANT:
 * The canonical commit event is generated at the point where
 * validator 1 has obtained the COMMIT quorum and successfully
 * appends the transaction block.
 *****************************************************************/

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');


/*****************************************************************
 * CONFIGURATION
 *****************************************************************/

const VALIDATOR_ID =
    Number(process.env.VALIDATOR_ID || '1');

const NODE_ID =
    process.env.NODE_ID ||
    `validator_${VALIDATOR_ID}`;

const RESULTS_ROOT =
    process.env.RESULTS_ROOT ||
    'results_C_fixed';

const NETWORK_NAME =
    process.env.NETWORK_NAME ||
    'myBlockchain_C';

const N =
    Number(process.env.PBFT_N || '4');

const F =
    Math.floor((N - 1) / 3);

const QUORUM =
    2 * F + 1;

const PORT_BASE =
    Number(process.env.PORT_BASE || '39000');

const SWARM_PORT =
    PORT_BASE + VALIDATOR_ID - 1;

const PEER_HOST =
    process.env.PEER_HOST ||
    '127.0.0.1';

const PBFT_TIMEOUT_MS =
    Number(process.env.PBFT_TIMEOUT || '20') * 1000;


/*****************************************************************
 * PATHS
 *****************************************************************/

const ROOT =
    path.resolve(RESULTS_ROOT);

const VALIDATOR_ROOT =
    path.join(
        ROOT,
        `validator_${VALIDATOR_ID}`
    );

const RESULTS_DIR =
    path.join(
        VALIDATOR_ROOT,
        'results'
    );

const DATA_DIR =
    path.join(
        VALIDATOR_ROOT,
        'data'
    );

const NETWORK_DIR =
    path.join(
        ROOT,
        'network'
    );

const PBFT_FILE =
    path.join(
        RESULTS_DIR,
        'pbft_metrics.csv'
    );

const COMMIT_LOG =
    path.join(
        RESULTS_DIR,
        'commit_ids.log'
    );

/*
 * NEW:
 * Machine-readable canonical commit event file.
 */
const COMMIT_EVENTS_FILE =
    path.join(
        RESULTS_DIR,
        'commit_events.csv'
    );

const BLOCKCHAIN_FILE =
    path.join(
        DATA_DIR,
        'blockchain.json'
    );

const READY_FILE =
    path.join(
        NETWORK_DIR,
        'ready.flag'
    );

const GENESIS = 'GENESIS';


/*****************************************************************
 * DIRECTORIES
 *****************************************************************/

[
    RESULTS_DIR,
    DATA_DIR,
    NETWORK_DIR
].forEach(
    dir =>
        fs.mkdirSync(
            dir,
            {
                recursive: true
            }
        )
);


/*****************************************************************
 * CSV HELPERS
 *****************************************************************/

function csvValue(value) {

    if (
        value === undefined ||
        value === null
    ) {
        return '';
    }

    const text =
        String(value);

    if (
        /[",\n]/.test(text)
    ) {

        return `"${text.replace(
            /"/g,
            '""'
        )}"`;
    }

    return text;
}


function appendCsv(
    file,
    header,
    values
) {

    if (
        !fs.existsSync(file) ||
        fs.statSync(file).size === 0
    ) {

        fs.writeFileSync(
            file,
            header + '\n',
            'utf8'
        );
    }

    fs.appendFileSync(
        file,
        values
            .map(csvValue)
            .join(',') +
        '\n',
        'utf8'
    );
}


/*****************************************************************
 * PBFT METRICS
 *****************************************************************/

const PBFT_HEADER = [
    'validator_id',
    'node_id',
    'tx_id',
    'digest',

    'consensus_start_timestamp',
    'preprepare_timestamp',
    'prepare_quorum_timestamp',
    'commit_timestamp',

    'consensus_start_timestamp_ms',
    'commit_timestamp_ms',

    'pbft_preprepare_ms',
    'pbft_prepare_ms',
    'pbft_commit_ms',
    'pbft_total_ms',

    'prepare_quorum',
    'commit_quorum',

    'validators_ready',
    'N',
    'F',

    'block_index',
    'blockchain_length',

    'primary_id',

    'recovery_of',
    'recovery_attempt'
].join(',');


/*****************************************************************
 * COMMIT EVENT METRICS
 *****************************************************************/

const COMMIT_EVENT_HEADER = [
    'validator_id',
    'node_id',
    'tx_id',
    'digest',

    'commit_timestamp',
    'commit_timestamp_ms',

    'block_index',
    'blockchain_length',

    'prepare_quorum',
    'commit_quorum',

    'N',
    'F',

    'recovery_of',
    'recovery_attempt'
].join(',');


/*****************************************************************
 * INITIALIZE FILES
 *****************************************************************/

if (
    !fs.existsSync(PBFT_FILE) ||
    fs.statSync(PBFT_FILE).size === 0
) {

    fs.writeFileSync(
        PBFT_FILE,
        PBFT_HEADER + '\n',
        'utf8'
    );
}

if (
    !fs.existsSync(COMMIT_EVENTS_FILE) ||
    fs.statSync(COMMIT_EVENTS_FILE).size === 0
) {

    fs.writeFileSync(
        COMMIT_EVENTS_FILE,
        COMMIT_EVENT_HEADER + '\n',
        'utf8'
    );
}


/*****************************************************************
 * UTILITY
 *****************************************************************/

function nowISO() {

    return new Date().toISOString();
}


function nowEpochMs() {

    return Date.now();
}


function hrMs(
    startNs,
    endNs
) {

    if (
        startNs === null ||
        startNs === undefined ||
        endNs === null ||
        endNs === undefined
    ) {
        return 0;
    }

    return Number(
        endNs - startNs
    ) / 1e6;
}


function sha256(data) {

    return crypto
        .createHash('sha256')
        .update(data)
        .digest('hex');
}


function sleep(ms) {

    return new Promise(
        resolve =>
            setTimeout(
                resolve,
                ms
            )
    );
}


/*****************************************************************
 * COMMIT LOG
 *****************************************************************/

function appendCommit(
    txId
) {

    if (
        fs.existsSync(COMMIT_LOG)
    ) {

        try {

            const existing =
                fs.readFileSync(
                    COMMIT_LOG,
                    'utf8'
                )
                .split(/\r?\n/)
                .filter(Boolean);

            if (
                existing.includes(txId)
            ) {
                return;
            }

        } catch (_) {}
    }

    fs.appendFileSync(
        COMMIT_LOG,
        `${txId}\n`,
        'utf8'
    );
}


/*****************************************************************
 * CANONICAL COMMIT EVENT
 *
 * This is the NEW authoritative event used by the camera
 * experiment to determine when the corresponding transaction
 * has reached canonical blockchain commit.
 *****************************************************************/

function appendCommitEvent(
    state,
    block
) {

    const commitTimestampMs =
        nowEpochMs();

    const commitTimestamp =
        new Date(
            commitTimestampMs
        ).toISOString();

    appendCsv(
        COMMIT_EVENTS_FILE,
        COMMIT_EVENT_HEADER,
        [

            VALIDATOR_ID,
            NODE_ID,

            state.tx.tx_id,
            state.tx.digest,

            commitTimestamp,
            commitTimestampMs,

            block.blockIndex,
            block.blockchainLength,

            state.prepare.size,
            state.commit.size,

            N,
            F,

            state.tx.recovery_of || '',
            state.tx.recovery_attempt ?? ''
        ]
    );

    return {
        commitTimestamp,
        commitTimestampMs
    };
}


/*****************************************************************
 * BLOCKCHAIN
 *****************************************************************/

function loadBlockchain() {

    if (
        !fs.existsSync(
            BLOCKCHAIN_FILE
        )
    ) {

        return [];
    }

    try {

        const raw =
            fs.readFileSync(
                BLOCKCHAIN_FILE,
                'utf8'
            );

        const data =
            JSON.parse(raw);

        if (
            Array.isArray(data)
        ) {

            return data;
        }

        if (
            data &&
            Array.isArray(data.blocks)
        ) {

            return data.blocks;
        }

        return [];

    } catch (error) {

        console.error(
            '[C] Blockchain read error:',
            error.message
        );

        return [];
    }
}


function saveBlockchain(
    blocks
) {

    fs.writeFileSync(
        BLOCKCHAIN_FILE,
        JSON.stringify(
            blocks,
            null,
            2
        ),
        'utf8'
    );
}


function appendBlock(
    tx
) {

    const blocks =
        loadBlockchain();

    const existing =
        blocks.find(
            block =>
                block &&
                block.tx_id === tx.tx_id
        );

    if (
        existing
    ) {

        return {

            blockIndex:
                existing.index,

            blockchainLength:
                blocks.length,

            duplicate:
                true
        };
    }

    const blockIndex =
        blocks.length;

    const previousHash =
        blockIndex > 0
            ? (
                blocks[
                    blockIndex - 1
                ].hash ||
                GENESIS
            )
            : GENESIS;

    const timestamp =
        nowISO();

    const blockBody = {

        index:
            blockIndex,

        timestamp,

        previous_hash:
            previousHash,

        tx_id:
            tx.tx_id,

        digest:
            tx.digest,

        transaction:
            tx
    };

    const hash =
        sha256(
            JSON.stringify(
                blockBody
            )
        );

    const block = {

        ...blockBody,

        hash
    };

    blocks.push(block);

    saveBlockchain(blocks);

    return {

        blockIndex,

        blockchainLength:
            blocks.length,

        duplicate:
            false
    };
}


/*****************************************************************
 * PEERS
 *****************************************************************/

function peerPort(
    validatorId
) {

    return (
        PORT_BASE +
        validatorId -
        1
    );
}


function allPeerIds() {

    const ids = [];

    for (
        let i = 1;
        i <= N;
        i++
    ) {

        ids.push(i);
    }

    return ids;
}


/*****************************************************************
 * NETWORK STATUS
 *****************************************************************/

function getValidatorDirectories() {

    try {

        return fs
            .readdirSync(ROOT)
            .filter(
                name =>
                    /^validator_[0-9]+$/
                        .test(name)
            );

    } catch (_) {

        return [];
    }
}


function validatorsReady() {

    const dirs =
        getValidatorDirectories();

    return Math.max(
        0,
        Math.min(
            dirs.length,
            N
        )
    );
}


function getNetworkStatus() {

    const readyCount =
        validatorsReady();

    return {

        ready:
            readyCount >= N,

        readyValidators:
            readyCount,

        expectedValidators:
            N,

        N,
        F,

        quorum:
            QUORUM,

        validatorId:
            VALIDATOR_ID,

        nodeId:
            NODE_ID,

        network:
            NETWORK_NAME
    };
}


/*****************************************************************
 * READY FLAG
 *****************************************************************/

function writeReadyFlag() {

    if (
        VALIDATOR_ID !== 1
    ) {
        return;
    }

    const status =
        getNetworkStatus();

    if (
        status.readyValidators < N
    ) {
        return;
    }

    fs.writeFileSync(
        READY_FILE,
        JSON.stringify(
            {

                ready: true,

                experiment: 'C',

                architecture:
                    'YOLOv8+MQTT+Plain-P2P+PBFT-style+Blockchain',

                network:
                    NETWORK_NAME,

                N,
                F,

                quorum:
                    QUORUM,

                validators_ready:
                    status.readyValidators,

                timestamp:
                    nowISO()
            },
            null,
            2
        ),
        'utf8'
    );

    console.log(
        `[C] NETWORK READY: ${N}/${N} validators`
    );
}


/*****************************************************************
 * PLAIN TCP P2P
 *****************************************************************/

function sendP2P(
    targetId,
    message
) {

    return new Promise(
        resolve => {

            if (
                targetId === VALIDATOR_ID
            ) {

                resolve(false);
                return;
            }

            const socket =
                new net.Socket();

            let finished = false;

            const finish =
                result => {

                    if (finished) {
                        return;
                    }

                    finished = true;

                    try {
                        socket.destroy();
                    } catch (_) {}

                    resolve(result);
                };

            socket.setTimeout(1500);

            socket.on(
                'timeout',
                () => finish(false)
            );

            socket.on(
                'error',
                () => finish(false)
            );

            socket.connect(
                peerPort(targetId),
                PEER_HOST,
                () => {

                    try {

                        socket.write(
                            JSON.stringify(message) +
                            '\n',
                            'utf8',
                            () => {

                                try {
                                    socket.end();
                                } catch (_) {}

                                finish(true);
                            }
                        );

                    } catch (_) {

                        finish(false);
                    }
                }
            );
        }
    );
}


async function broadcast(
    message
) {

    const results = [];

    for (
        const peer of allPeerIds()
    ) {

        if (
            peer === VALIDATOR_ID
        ) {
            continue;
        }

        results.push(
            await sendP2P(
                peer,
                message
            )
        );
    }

    return results;
}


/*****************************************************************
 * PBFT STATE
 *****************************************************************/

const consensusStates =
    new Map();

const seenTransactions =
    new Set();


/*****************************************************************
 * QUORUM
 *****************************************************************/

function quorumReached(
    set
) {

    return (
        set.size >= QUORUM
    );
}


/*****************************************************************
 * WRITE PBFT METRIC
 *****************************************************************/

function writeMetric(
    metric
) {

    appendCsv(
        PBFT_FILE,
        PBFT_HEADER,
        [

            metric.validator_id,
            metric.node_id,
            metric.tx_id,
            metric.digest,

            metric.consensus_start_timestamp,
            metric.preprepare_timestamp,
            metric.prepare_quorum_timestamp,
            metric.commit_timestamp,

            metric.consensus_start_timestamp_ms,
            metric.commit_timestamp_ms,

            metric.pbft_preprepare_ms,
            metric.pbft_prepare_ms,
            metric.pbft_commit_ms,
            metric.pbft_total_ms,

            metric.prepare_quorum,
            metric.commit_quorum,

            metric.validators_ready,
            metric.N,
            metric.F,

            metric.block_index,
            metric.blockchain_length,

            metric.primary_id,

            metric.recovery_of,
            metric.recovery_attempt
        ]
    );
}


/*****************************************************************
 * PREPARE / COMMIT BROADCAST
 *****************************************************************/

async function broadcastPrepare(tx) {

    return broadcast({

        type: 'PBFT_PREPARE',

        network: NETWORK_NAME,

        validator_id:
            VALIDATOR_ID,

        tx_id:
            tx.tx_id,

        digest:
            tx.digest
    });
}


async function broadcastCommit(tx) {

    return broadcast({

        type: 'PBFT_COMMIT',

        network: NETWORK_NAME,

        validator_id:
            VALIDATOR_ID,

        tx_id:
            tx.tx_id,

        digest:
            tx.digest
    });
}


/*****************************************************************
 * FINALIZE PRIMARY
 *****************************************************************/

function finalizePrimary(
    state
) {

    if (
        !state ||
        state.committed
    ) {
        return false;
    }

    if (
        !quorumReached(state.prepare)
    ) {
        return false;
    }

    if (
        !quorumReached(state.commit)
    ) {
        return false;
    }

    if (
        state.prepareNs === null
    ) {

        state.prepareNs =
            process.hrtime.bigint();
    }

    if (
        state.commitNs === null
    ) {

        state.commitNs =
            process.hrtime.bigint();
    }

    /*
     * Canonical blockchain commit:
     *
     * The transaction has obtained the required PBFT commit
     * quorum and is now appended to the local blockchain.
     */

    const block =
        appendBlock(state.tx);

    state.committed = true;

    const commitEvent =
        appendCommitEvent(
            state,
            block
        );

    appendCommit(
        state.tx.tx_id
    );

    const prepareMs =
        hrMs(
            state.preprepareNs,
            state.prepareNs
        );

    const commitMs =
        hrMs(
            state.prepareNs,
            state.commitNs
        );

    const totalMs =
        hrMs(
            state.startNs,
            state.commitNs
        );

    writeMetric({

        validator_id:
            VALIDATOR_ID,

        node_id:
            NODE_ID,

        tx_id:
            state.tx.tx_id,

        digest:
            state.tx.digest,

        consensus_start_timestamp:
            state.consensusStart,

        preprepare_timestamp:
            state.preprepareTimestamp,

        prepare_quorum_timestamp:
            state.prepareTimestamp,

        commit_timestamp:
            commitEvent.commitTimestamp,

        consensus_start_timestamp_ms:
            state.consensusStartEpochMs,

        commit_timestamp_ms:
            commitEvent.commitTimestampMs,

        pbft_preprepare_ms:
            0,

        pbft_prepare_ms:
            prepareMs.toFixed(6),

        pbft_commit_ms:
            commitMs.toFixed(6),

        pbft_total_ms:
            totalMs.toFixed(6),

        prepare_quorum:
            state.prepare.size,

        commit_quorum:
            state.commit.size,

        validators_ready:
            validatorsReady(),

        N,
        F,

        block_index:
            block.blockIndex,

        blockchain_length:
            block.blockchainLength,

        primary_id:
            'validator_1',

        recovery_of:
            state.tx.recovery_of || '',

        recovery_attempt:
            state.tx.recovery_attempt ?? ''
    });

    console.log(
        `[C] COMMITTED ` +
        `tx=${state.tx.tx_id} ` +
        `prepare=${state.prepare.size}/${QUORUM} ` +
        `commit=${state.commit.size}/${QUORUM} ` +
        `block=${block.blockIndex}`
    );

    consensusStates.delete(
        state.tx.tx_id
    );

    return true;
}


/*****************************************************************
 * START PBFT
 *****************************************************************/

async function startPBFT(
    tx
) {

    if (
        !tx ||
        !tx.tx_id
    ) {
        return false;
    }

    if (
        VALIDATOR_ID !== 1
    ) {
        return false;
    }

    if (
        seenTransactions.has(tx.tx_id)
    ) {
        return false;
    }

    seenTransactions.add(tx.tx_id);

    const startNs =
        process.hrtime.bigint();

    const startEpochMs =
        nowEpochMs();

    const state = {

        tx,

        startNs,

        startEpochMs,

        preprepareNs:
            process.hrtime.bigint(),

        prepareNs: null,
        commitNs: null,

        prepare:
            new Set([1]),

        commit:
            new Set([1]),

        committed: false,

        commitBroadcasted: false,

        consensusStart:
            nowISO(),

        consensusStartEpochMs:
            startEpochMs,

        preprepareTimestamp:
            nowISO(),

        prepareTimestamp: null
    };

    consensusStates.set(
        tx.tx_id,
        state
    );

    console.log(
        `[C] PBFT START tx=${tx.tx_id}`
    );

    await broadcast({

        type:
            'PBFT_PREPREPARE',

        network:
            NETWORK_NAME,

        validator_id:
            1,

        tx_id:
            tx.tx_id,

        digest:
            tx.digest,

        transaction:
            tx
    });

    await broadcastPrepare(tx);

    const prepareDeadline =
        Date.now() +
        PBFT_TIMEOUT_MS;

    while (
        Date.now() <
        prepareDeadline
    ) {

        if (
            quorumReached(state.prepare)
        ) {
            break;
        }

        await sleep(2);
    }

    if (
        !quorumReached(state.prepare)
    ) {

        console.error(
            `[C] PREPARE TIMEOUT ` +
            `tx=${tx.tx_id} ` +
            `received=${state.prepare.size}/${QUORUM}`
        );

        consensusStates.delete(
            tx.tx_id
        );

        return false;
    }

    state.prepareNs =
        process.hrtime.bigint();

    state.prepareTimestamp =
        nowISO();

    if (
        !state.commitBroadcasted
    ) {

        state.commitBroadcasted = true;

        await broadcastCommit(tx);
    }

    const commitDeadline =
        Date.now() +
        PBFT_TIMEOUT_MS;

    while (
        Date.now() <
        commitDeadline
    ) {

        if (
            quorumReached(state.commit)
        ) {
            break;
        }

        await sleep(2);
    }

    if (
        !quorumReached(state.commit)
    ) {

        console.error(
            `[C] COMMIT TIMEOUT ` +
            `tx=${tx.tx_id} ` +
            `received=${state.commit.size}/${QUORUM}`
        );

        consensusStates.delete(
            tx.tx_id
        );

        return false;
    }

    state.commitNs =
        process.hrtime.bigint();

    finalizePrimary(state);

    return true;
}


/*****************************************************************
 * PUBLIC API
 *****************************************************************/

function submitTx(tx) {

    if (
        !tx ||
        !tx.tx_id
    ) {
        return false;
    }

    if (
        VALIDATOR_ID !== 1
    ) {
        return false;
    }

    tx.tx_id =
        String(tx.tx_id);

    tx.transaction_id =
        tx.transaction_id ||
        tx.tx_id;

    tx.id =
        tx.id ||
        tx.tx_id;

    if (
        !tx.digest
    ) {

        tx.digest =
            sha256(
                JSON.stringify(tx)
            );
    }

    startPBFT(tx)
        .catch(
            error =>
                console.error(
                    '[C] PBFT error:',
                    error.stack || error
                )
        );

    return true;
}


/*****************************************************************
 * PRE-PREPARE HANDLER
 *****************************************************************/

async function handlePrePrepare(
    message
) {

    if (
        !message ||
        !message.tx_id ||
        !message.digest ||
        !message.transaction
    ) {
        return;
    }

    if (
        VALIDATOR_ID === 1
    ) {
        return;
    }

    if (
        seenTransactions.has(message.tx_id)
    ) {
        return;
    }

    const tx = {
        ...message.transaction
    };

    tx.tx_id =
        String(message.tx_id);

    tx.transaction_id =
        tx.transaction_id ||
        tx.tx_id;

    tx.id =
        tx.id ||
        tx.tx_id;

    tx.digest =
        message.digest;

    seenTransactions.add(
        tx.tx_id
    );

    const state = {

        tx,

        startNs:
            process.hrtime.bigint(),

        preprepareNs:
            process.hrtime.bigint(),

        prepareNs: null,
        commitNs: null,

        prepare:
            new Set([VALIDATOR_ID]),

        commit:
            new Set([VALIDATOR_ID]),

        committed: false,

        commitBroadcasted: false,

        prepareSent: false,
        commitSent: false,

        consensusStart:
            nowISO(),

        consensusStartEpochMs:
            nowEpochMs(),

        preprepareTimestamp:
            nowISO(),

        prepareTimestamp: null
    };

    consensusStates.set(
        tx.tx_id,
        state
    );

    if (
        !state.prepareSent
    ) {

        state.prepareSent = true;

        await sendP2P(
            1,
            {

                type:
                    'PBFT_PREPARE',

                network:
                    NETWORK_NAME,

                validator_id:
                    VALIDATOR_ID,

                tx_id:
                    tx.tx_id,

                digest:
                    tx.digest
            }
        );
    }
}


/*****************************************************************
 * PREPARE HANDLER
 *****************************************************************/

async function handlePrepare(
    message
) {

    if (
        !message ||
        !message.tx_id ||
        !message.digest
    ) {
        return;
    }

    const state =
        consensusStates.get(
            message.tx_id
        );

    if (!state) {
        return;
    }

    if (
        message.digest !== state.tx.digest
    ) {
        return;
    }

    const validatorId =
        Number(message.validator_id);

    if (
        !Number.isInteger(validatorId) ||
        validatorId < 1 ||
        validatorId > N
    ) {
        return;
    }

    state.prepare.add(
        validatorId
    );

    if (
        VALIDATOR_ID !== 1
    ) {
        return;
    }

    if (
        quorumReached(state.prepare) &&
        !state.commitBroadcasted
    ) {

        state.prepareNs =
            process.hrtime.bigint();

        state.prepareTimestamp =
            nowISO();

        state.commitBroadcasted = true;

        await broadcastCommit(
            state.tx
        );
    }
}


/*****************************************************************
 * COMMIT HANDLER
 *****************************************************************/

async function handleCommit(
    message
) {

    if (
        !message ||
        !message.tx_id ||
        !message.digest
    ) {
        return;
    }

    const state =
        consensusStates.get(
            message.tx_id
        );

    if (!state) {
        return;
    }

    if (
        message.digest !== state.tx.digest
    ) {
        return;
    }

    const validatorId =
        Number(message.validator_id);

    if (
        !Number.isInteger(validatorId) ||
        validatorId < 1 ||
        validatorId > N
    ) {
        return;
    }

    state.commit.add(
        validatorId
    );

    if (
        VALIDATOR_ID === 1
    ) {

        if (
            quorumReached(state.commit) &&
            !state.committed
        ) {

            state.commitNs =
                process.hrtime.bigint();

            finalizePrimary(
                state
            );
        }

        return;
    }

    if (
        validatorId === 1 &&
        !state.commitSent
    ) {

        state.commitSent = true;

        state.commit.add(
            VALIDATOR_ID
        );

        await sendP2P(
            1,
            {

                type:
                    'PBFT_COMMIT',

                network:
                    NETWORK_NAME,

                validator_id:
                    VALIDATOR_ID,

                tx_id:
                    state.tx.tx_id,

                digest:
                    state.tx.digest
            }
        );
    }
}


/*****************************************************************
 * TCP SERVER
 *****************************************************************/

const server =
    net.createServer(
        socket => {

            let buffer = '';

            socket.on(
                'data',
                data => {

                    buffer +=
                        data.toString('utf8');

                    let index;

                    while (
                        (
                            index =
                                buffer.indexOf('\n')
                        ) !== -1
                    ) {

                        const line =
                            buffer.slice(
                                0,
                                index
                            );

                        buffer =
                            buffer.slice(
                                index + 1
                            );

                        if (
                            !line.trim()
                        ) {
                            continue;
                        }

                        let message;

                        try {

                            message =
                                JSON.parse(line);

                        } catch (_) {

                            continue;
                        }

                        try {

                            if (
                                message.type ===
                                'PBFT_PREPREPARE'
                            ) {

                                handlePrePrepare(
                                    message
                                ).catch(
                                    console.error
                                );

                            } else if (
                                message.type ===
                                'PBFT_PREPARE'
                            ) {

                                handlePrepare(
                                    message
                                ).catch(
                                    console.error
                                );

                            } else if (
                                message.type ===
                                'PBFT_COMMIT'
                            ) {

                                handleCommit(
                                    message
                                ).catch(
                                    console.error
                                );
                            }

                        } catch (error) {

                            console.error(
                                '[C] P2P handler error:',
                                error.stack || error
                            );
                        }
                    }
                }
            );

            socket.on(
                'error',
                () => {}
            );
        }
    );


/*****************************************************************
 * START SERVER
 *****************************************************************/

server.listen(
    SWARM_PORT,
    PEER_HOST,
    () => {

        console.log(
            '================================================'
        );

        console.log(
            'YOLOChain - Experiment C Validator'
        );

        console.log(
            '================================================'
        );

        console.log(
            `Validator ID : ${VALIDATOR_ID}`
        );

        console.log(
            `Node ID      : ${NODE_ID}`
        );

        console.log(
            `Network      : ${NETWORK_NAME}`
        );

        console.log(
            `P2P port     : ${SWARM_PORT}`
        );

        console.log(
            `N            : ${N}`
        );

        console.log(
            `F            : ${F}`
        );

        console.log(
            `Quorum       : ${QUORUM}`
        );

        console.log(
            'PQC          : OFF'
        );

        console.log(
            'KEM          : OFF'
        );

        console.log(
            'AES          : OFF'
        );

        console.log(
            'Signatures   : OFF'
        );

        console.log(
            '================================================'
        );

        if (
            VALIDATOR_ID === 1
        ) {

            const readyMonitor =
                setInterval(
                    () => {

                        writeReadyFlag();

                        const status =
                            getNetworkStatus();

                        if (
                            status.ready
                        ) {

                            clearInterval(
                                readyMonitor
                            );
                        }

                    },
                    500
                );
        }
    });


/*****************************************************************
 * STDIN TEST INTERFACE
 *****************************************************************/

process.stdin.setEncoding('utf8');

process.stdin.on(
    'data',
    data => {

        const lines =
            data.toString().split('\n');

        for (
            const line of lines
        ) {

            if (
                !line.trim()
            ) {
                continue;
            }

            try {

                const tx =
                    JSON.parse(line);

                if (
                    tx &&
                    tx.tx_id
                ) {

                    if (
                        !tx.digest
                    ) {

                        tx.digest =
                            sha256(
                                JSON.stringify(tx)
                            );
                    }

                    submitTx(tx);
                }

            } catch (_) {}
        }
    }
);


/*****************************************************************
 * EXPORTS
 *****************************************************************/

module.exports = {

    submitTx,

    getNetworkStatus,

    sha256,

    loadBlockchain
};


/*****************************************************************
 * SHUTDOWN
 *****************************************************************/

function shutdown() {

    console.log(
        `[C] Validator ${VALIDATOR_ID} shutting down.`
    );

    try {
        server.close();
    } catch (_) {}

    process.exit(0);
}


process.on(
    'SIGINT',
    shutdown
);

process.on(
    'SIGTERM',
    shutdown
);
