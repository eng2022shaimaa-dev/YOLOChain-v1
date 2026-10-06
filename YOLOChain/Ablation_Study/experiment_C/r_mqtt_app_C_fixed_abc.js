#!/usr/bin/env node

'use strict';

/*****************************************************************
 * YOLOChain
 * Experiment C - MQTT Gateway / Validator 1
 *****************************************************************/

const fs =
    require('fs');

const path =
    require('path');

const crypto =
    require('crypto');

const mqtt =
    require('mqtt');

const p2p =
    require('./p2p_blockchain2_C_fixed_abc');


/*****************************************************************
 * CONFIGURATION
 *****************************************************************/

const VALIDATOR_ID =
    String(
        process.env.VALIDATOR_ID || '1'
    );

const NODE_ID =
    process.env.NODE_ID ||
    `validator_${VALIDATOR_ID}`;

const RESULTS_ROOT =
    process.env.RESULTS_ROOT ||
    'results_C_fixed';

const BROKER =
    process.env.MQTT_BROKER ||
    'mqtt://localhost:1883';

const TOPIC =
    process.env.MQTT_TOPIC ||
    'yolochain/C';

/*
 * NEW:
 * Camera subscribes to this topic to receive the canonical
 * blockchain commit event for the same transaction.
 */
const COMMIT_TOPIC =
    process.env.MQTT_COMMIT_TOPIC ||
    'yolochain/C/commit';

const PBFT_N =
    Number(
        process.env.PBFT_N || '4'
    );


/*****************************************************************
 * PATHS
 *****************************************************************/

const VALIDATOR_DIR =
    path.join(
        RESULTS_ROOT,
        `validator_${VALIDATOR_ID}`
    );

const RESULTS_DIR =
    path.join(
        VALIDATOR_DIR,
        'results'
    );

const NETWORK_DIR =
    path.join(
        RESULTS_ROOT,
        'network'
    );

const METRICS_FILE =
    path.join(
        RESULTS_DIR,
        'node_metrics.csv'
    );

const READY_FLAG =
    path.join(
        NETWORK_DIR,
        'ready.flag'
    );


[
    RESULTS_DIR,
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
 * STARTUP
 *****************************************************************/

console.log(
    '================================================'
);

console.log(
    'YOLOChain - Experiment C MQTT Gateway'
);

console.log(
    '================================================'
);

console.log(
    `NODE_ID        = ${NODE_ID}`
);

console.log(
    `VALIDATOR_ID   = ${VALIDATOR_ID}`
);

console.log(
    `MQTT_BROKER    = ${BROKER}`
);

console.log(
    `MQTT_TOPIC     = ${TOPIC}`
);

console.log(
    `COMMIT_TOPIC   = ${COMMIT_TOPIC}`
);

console.log(
    `PBFT_N         = ${PBFT_N}`
);

console.log(
    'PQC            = OFF'
);

console.log(
    'KEM            = OFF'
);

console.log(
    'AES            = OFF'
);

console.log(
    'SIGNATURES     = OFF'
);

console.log(
    '================================================'
);


/*****************************************************************
 * CSV HEADER
 *****************************************************************/

const HEADER = [

    'validator_id',
    'node_id',

    'node_receive_timestamp',
    'node_receive_timestamp_ms',

    'mqtt_topic',

    'tx_id',

    'source_timestamp_ms',

    'camera_id',

    'dataset',

    'run_id',

    'sequence',

    'image',

    'image_index',

    'frame_id',

    'frame_file',

    'detection_count',

    'transaction_processing_ms',

    'node_processing_ms',

    'p2p_submit_call_ms',

    'mqtt_to_node_ms',

    'python_pipeline_ms',

    'yolo_inference_ms',

    'postprocessing_ms',

    'json_generation_ms',

    'mqtt_transmission_ms',

    'model',

    'image_size',

    'confidence_threshold',

    'iou_threshold',

    'recovery_of',

    'recovery_attempt'

].join(',') + '\n';


if (
    !fs.existsSync(METRICS_FILE) ||
    fs.statSync(METRICS_FILE).size === 0
) {

    fs.writeFileSync(
        METRICS_FILE,
        HEADER,
        'utf8'
    );
}


/*****************************************************************
 * CSV HELPERS
 *****************************************************************/

function csv(value) {

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


function appendRow(values) {

    fs.appendFileSync(
        METRICS_FILE,
        values
            .map(csv)
            .join(',') +
        '\n',
        'utf8'
    );
}


function num(
    value,
    fallback = 0
) {

    const n =
        Number(value);

    return Number.isFinite(n)
        ? n
        : fallback;
}


function firstDefined(
    ...values
) {

    for (
        const value of values
    ) {

        if (
            value !== undefined &&
            value !== null
        ) {

            return value;
        }
    }

    return undefined;
}


function makeTxId() {

    if (
        typeof crypto.randomUUID ===
        'function'
    ) {

        return crypto.randomUUID();
    }

    return crypto
        .randomBytes(16)
        .toString('hex');
}


/*****************************************************************
 * NETWORK READY
 *****************************************************************/

function isNetworkReady() {

    try {

        if (
            !fs.existsSync(
                READY_FLAG
            )
        ) {

            return false;
        }

        const raw =
            fs.readFileSync(
                READY_FLAG,
                'utf8'
            );

        const data =
            JSON.parse(raw);

        return (
            data &&
            data.ready === true &&
            Number(
                data.validators_ready
            ) >= PBFT_N
        );

    } catch (_) {

        return false;
    }
}


async function waitForNetworkReady() {

    const timeoutMs =
        30 * 1000;

    const started =
        Date.now();

    console.log(
        `[C] Waiting for ${PBFT_N} validators...`
    );

    while (
        Date.now() -
        started <
        timeoutMs
    ) {

        if (
            isNetworkReady()
        ) {

            console.log(
                '[C] Validator network READY'
            );

            return true;
        }

        await new Promise(
            resolve =>
                setTimeout(
                    resolve,
                    250
                )
        );
    }

    throw new Error(
        `Validator network was not ready after ${timeoutMs / 1000}s`
    );
}


/*****************************************************************
 * MQTT CLIENT
 *****************************************************************/

const client =
    mqtt.connect(
        BROKER,
        {

            clientId:
                `yolochain-C-${VALIDATOR_ID}-` +
                crypto
                    .randomBytes(4)
                    .toString('hex'),

            clean: true,

            reconnectPeriod: 1000,

            connectTimeout: 10000
        }
    );


/*****************************************************************
 * MQTT CONNECT
 *****************************************************************/

client.on(
    'connect',
    () => {

        console.log(
            `[C] MQTT connected: ${BROKER}`
        );

        client.subscribe(
            TOPIC,
            {
                qos: 1
            },
            error => {

                if (error) {

                    console.error(
                        '[C] MQTT subscribe error:',
                        error.message
                    );

                    return;
                }

                console.log(
                    `[C] subscribed: ${TOPIC}`
                );
            }
        );

        /*
         * NEW:
         * Subscribe to canonical commit notifications.
         *
         * This allows the camera process to receive a direct
         * commit event without polling blockchain.json.
         */
        client.subscribe(
            COMMIT_TOPIC,
            {
                qos: 1
            },
            error => {

                if (error) {

                    console.error(
                        '[C] Commit-topic subscribe error:',
                        error.message
                    );

                    return;
                }

                console.log(
                    `[C] subscribed: ${COMMIT_TOPIC}`
                );
            }
        );
    }
);


/*****************************************************************
 * MQTT ERROR
 *****************************************************************/

client.on(
    'error',
    error => {

        console.error(
            '[C] MQTT error:',
            error.message
        );
    }
);


/*****************************************************************
 * MQTT MESSAGE
 *****************************************************************/

client.on(
    'message',
    (
        topic,
        buffer
    ) => {

        /*
         * Commit notifications are handled separately.
         */
        if (
            topic === COMMIT_TOPIC
        ) {

            /*
             * This message is deliberately retained only as an
             * event source. The camera experiment can subscribe
             * to the same topic using its own MQTT client.
             */

            return;
        }

        const receiveEpoch =
            Date.now();

        const start =
            process.hrtime.bigint();

        try {

            const payload =
                JSON.parse(
                    buffer.toString('utf8')
                );

            const msg =
                payload &&
                payload.message &&
                typeof payload.message === 'object'
                    ? payload.message
                    : payload;

            const txId =
                String(
                    firstDefined(

                        payload.transaction_id,
                        msg.transaction_id,

                        payload.tx_id,
                        msg.tx_id,

                        payload.id,
                        msg.id,

                        makeTxId()
                    )
                );

            const timing =
                firstDefined(
                    payload.timing,
                    msg.timing,
                    {}
                ) || {};

            const sourceTimestamp =
                num(
                    firstDefined(

                        payload.timestamp_ms,
                        msg.timestamp_ms,

                        payload.detection_timestamp,
                        msg.detection_timestamp
                    ),
                    receiveEpoch
                );


            /*****************************************************
             * TRANSACTION
             *****************************************************/

            const tx = {

                id:
                    txId,

                transaction_id:
                    txId,

                tx_id:
                    txId,

                camera_id:
                    firstDefined(
                        payload.camera_id,
                        msg.camera_id,
                        ''
                    ),

                dataset:
                    firstDefined(
                        payload.dataset,
                        msg.dataset,
                        ''
                    ),

                run_id:
                    firstDefined(
                        payload.run_id,
                        msg.run_id,
                        ''
                    ),

                sequence:
                    firstDefined(
                        payload.sequence,
                        msg.sequence,
                        ''
                    ),

                image:
                    firstDefined(
                        payload.image,
                        msg.image,
                        ''
                    ),

                image_index:
                    firstDefined(
                        payload.image_index,
                        msg.image_index,
                        ''
                    ),

                frame_id:
                    firstDefined(
                        payload.frame_id,
                        msg.frame_id,
                        ''
                    ),

                frame_file:
                    firstDefined(
                        payload.frame_file,
                        msg.frame_file,
                        ''
                    ),

                detection_count:
                    num(
                        firstDefined(
                            payload.detection_count,
                            msg.detection_count
                        ),
                        0
                    ),

                detections:
                    firstDefined(
                        payload.detections,
                        msg.detections,
                        []
                    ),

                timestamp_ms:
                    sourceTimestamp,

                recovery_of:
                    firstDefined(
                        payload.recovery_of,
                        msg.recovery_of,
                        ''
                    ),

                recovery_attempt:
                    firstDefined(
                        payload.recovery_attempt,
                        msg.recovery_attempt,
                        ''
                    ),

                model:
                    firstDefined(
                        payload.model,
                        msg.model,
                        ''
                    ),

                img_size:
                    firstDefined(
                        payload.img_size,
                        msg.img_size,
                        payload.image_size,
                        msg.image_size,
                        ''
                    ),

                conf_threshold:
                    firstDefined(
                        payload.conf_threshold,
                        msg.conf_threshold,
                        payload.confidence_threshold,
                        msg.confidence_threshold,
                        ''
                    ),

                iou_threshold:
                    firstDefined(
                        payload.iou_threshold,
                        msg.iou_threshold,
                        ''
                    ),

                source_timing: {

                    python_pipeline_ms:
                        num(
                            firstDefined(
                                timing.python_pipeline_ms,
                                payload.python_pipeline_ms,
                                msg.python_pipeline_ms
                            ),
                            0
                        ),

                    yolo_inference_ms:
                        num(
                            firstDefined(
                                timing.yolo_inference_ms,
                                payload.yolo_inference_ms,
                                msg.yolo_inference_ms
                            ),
                            0
                        ),

                    postprocessing_ms:
                        num(
                            firstDefined(
                                timing.postprocessing_ms,
                                payload.postprocessing_ms,
                                msg.postprocessing_ms
                            ),
                            0
                        ),

                    json_generation_ms:
                        num(
                            firstDefined(
                                timing.json_generation_ms,
                                payload.json_generation_ms,
                                msg.json_generation_ms
                            ),
                            0
                        ),

                    mqtt_transmission_ms:
                        num(
                            firstDefined(
                                timing.mqtt_transmission_ms,
                                payload.mqtt_transmission_ms,
                                msg.mqtt_transmission_ms
                            ),
                            0
                        )
                }
            };


            tx.mqtt_to_node_ms =
                Math.max(
                    0,
                    receiveEpoch -
                    sourceTimestamp
                );


            /*****************************************************
             * SUBMIT TO PBFT
             *****************************************************/

            const submitStart =
                process.hrtime.bigint();

            const submitted =
                p2p.submitTx(tx);

            const submitMs =
                Number(
                    process.hrtime.bigint() -
                    submitStart
                ) / 1e6;


            const processingMs =
                Number(
                    process.hrtime.bigint() -
                    start
                ) / 1e6;


            /*****************************************************
             * NODE METRICS
             *****************************************************/

            appendRow([

                VALIDATOR_ID,

                NODE_ID,

                new Date(
                    receiveEpoch
                ).toISOString(),

                receiveEpoch,

                topic,

                txId,

                sourceTimestamp,

                tx.camera_id,

                tx.dataset,

                tx.run_id,

                tx.sequence,

                tx.image,

                tx.image_index,

                tx.frame_id,

                tx.frame_file,

                tx.detection_count,

                processingMs,

                processingMs,

                submitMs,

                tx.mqtt_to_node_ms,

                tx.source_timing
                    .python_pipeline_ms,

                tx.source_timing
                    .yolo_inference_ms,

                tx.source_timing
                    .postprocessing_ms,

                tx.source_timing
                    .json_generation_ms,

                tx.source_timing
                    .mqtt_transmission_ms,

                tx.model,

                tx.img_size,

                tx.conf_threshold,

                tx.iou_threshold,

                tx.recovery_of,

                tx.recovery_attempt
            ]);

            console.log(

                `[C] ${submitted ? 'SUBMITTED' : 'REJECTED'} ` +
                `tx=${txId} ` +
                `run=${tx.run_id} ` +
                `frame=${tx.frame_id} ` +
                `detections=${tx.detection_count} ` +
                `submit=${submitMs.toFixed(3)} ms`
            );

        } catch (error) {

            console.error(
                '[C] MQTT payload error:',
                error.stack || error
            );
        }
    }
);


/*****************************************************************
 * NETWORK STATUS
 *****************************************************************/

const networkMonitor =
    setInterval(
        () => {

            try {

                const status =
                    p2p.getNetworkStatus();

                console.log(

                    `[C] P2P status: ` +
                    `${status.readyValidators}/` +
                    `${status.expectedValidators} ` +
                    `validators | ` +
                    `quorum=${status.quorum}`
                );

            } catch (error) {

                console.error(
                    '[C] status error:',
                    error.message
                );
            }

        },
        5000
    );


/*****************************************************************
 * STARTUP
 *****************************************************************/

waitForNetworkReady()
    .catch(
        error => {

            console.error(
                '[C] Startup readiness failure:',
                error.message
            );

            process.exit(1);
        }
    );


/*****************************************************************
 * SHUTDOWN
 *****************************************************************/

function shutdown() {

    console.log(
        `[C] Shutting down ${NODE_ID}`
    );

    clearInterval(
        networkMonitor
    );

    try {
        client.end(true);
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

process.on(
    'uncaughtException',
    error => {

        console.error(
            '[C] uncaughtException:',
            error.stack || error
        );
    }
);

process.on(
    'unhandledRejection',
    error => {

        console.error(
            '[C] unhandledRejection:',
            error
        );
    }
);
