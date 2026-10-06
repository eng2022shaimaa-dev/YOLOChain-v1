#!/usr/bin/env node

"use strict";

const crypto = require("crypto");
const ffi = require("ffi-napi");
const ref = require("ref-napi");
const mqtt = require("mqtt");
const fs = require("fs");
const path = require("path");


/* ============================================================
   CONFIGURATION
   ============================================================ */

const MQTT_BROKER =
  "mqtt://localhost:1883";


const MQTT_TOPICS = [

  "pqc/handshake",
  "pqc1/handshake"

];


const VALIDATOR_ID =
  String(
    process.env.VALIDATOR_ID ||
    "1"
  );


const NODE_ID =
  process.env.NODE_ID ||
  `validator_${VALIDATOR_ID}`;


const IS_MQTT_GATEWAY =
  VALIDATOR_ID === "1";


const DEFAULT_PQC_ALGO_CODE =
  "2";


/* ============================================================
   SECURITY
   ============================================================ */

const SECURITY_MODE =
  String(
    process.env.SECURITY_MODE ||
    "0"
  ) === "1";


const SECURITY_TEST =
  String(
    process.env.SECURITY_TEST ||
    ""
  ).toUpperCase();


const AUTHORIZED_CAMERAS =
  new Set(
    String(
      process.env.AUTHORIZED_CAMERAS ||
      "camera_01"
    )
      .split(",")
      .map(
        x => x.trim()
      )
      .filter(
        Boolean
      )
  );


/* ============================================================
   PATHS
   ============================================================ */

const ROOT_RESULTS_DIR =
  path.join(
    __dirname,
    process.env.RESULTS_ROOT ||
      "results_D"
  );


const VALIDATOR_DIR =
  path.join(
    ROOT_RESULTS_DIR,
    `validator_${VALIDATOR_ID}`
  );


const RESULTS_DIR =
  path.join(
    VALIDATOR_DIR,
    "results"
  );


const DATA_DIR =
  path.join(
    VALIDATOR_DIR,
    "data"
  );


const SECURITY_DIR =
  path.join(
    ROOT_RESULTS_DIR,
    "security"
  );


fs.mkdirSync(
  RESULTS_DIR,
  {
    recursive: true
  }
);


fs.mkdirSync(
  DATA_DIR,
  {
    recursive: true
  }
);


if (
  SECURITY_MODE
) {

  fs.mkdirSync(
    SECURITY_DIR,
    {
      recursive: true
    }
  );

}


const NODE_METRICS_FILE =
  path.join(
    RESULTS_DIR,
    "node_metrics.csv"
  );


const SECURITY_METRICS_FILE =
  path.join(
    SECURITY_DIR,
    "security_metrics.csv"
  );


/* ============================================================
   STARTUP
   ============================================================ */

console.log(
  "\n============================================================"
);

console.log(
  "YOLOChain - Experiment D"
);

console.log(
  "MQTT + PQC + P2P + PBFT + Blockchain"
);

console.log(
  "============================================================"
);

console.log(
  "Validator ID :",
  VALIDATOR_ID
);

console.log(
  "Node ID      :",
  NODE_ID
);

console.log(
  "MQTT Gateway :",
  IS_MQTT_GATEWAY
    ? "YES"
    : "NO"
);

console.log(
  "Security mode:",
  SECURITY_MODE
    ? "ON"
    : "OFF"
);

console.log(
  "Results dir  :",
  RESULTS_DIR
);

console.log(
  "============================================================\n"
);


/* ============================================================
   P2P
   ============================================================ */

const p2p =
  require(
    "./p2p_blockchain_D_sec"
  );


/* ============================================================
   NORMAL NODE CSV
   ============================================================ */

const CSV_HEADER = [

  "validator_id",
  "node_id",

  "node_receive_timestamp",
  "node_receive_timestamp_ms",

  "mqtt_topic",

  "tx_id",

  "source_timestamp_ms",

  "camera_id",

  "dataset",

  "sequence",

  "image",

  "image_index",

  "frame_id",

  "frame_file",

  "detection_count",

  "pqc_algorithm",

  "pqc_algorithm_code",

  "pqc_verification_ms",

  "transaction_processing_ms",

  "node_processing_ms",

  "p2p_submit_call_ms",

  "mqtt_to_node_ms",

  "python_pipeline_ms",

  "yolo_inference_ms",

  "postprocessing_ms",

  "json_generation_ms",

  "pqc_signing_ms",

  "mqtt_transmission_ms",

  "model",

  "image_size",

  "confidence_threshold",

  "iou_threshold"

].join(",");


if (
  !fs.existsSync(
    NODE_METRICS_FILE
  )
) {

  fs.writeFileSync(
    NODE_METRICS_FILE,
    CSV_HEADER + "\n"
  );

}


/* ============================================================
   SECURITY CSV
   ============================================================ */

const SECURITY_CSV_HEADER = [

  "test_id",
  "run_id",
  "attack_type",
  "transaction_id",
  "camera_id",
  "sequence",
  "expected_result",
  "actual_result",
  "accepted",
  "detected",
  "rejection_reason",
  "signature_valid",
  "camera_authorized",
  "sequence_valid",
  "duplicate_tx",
  "offchain_hash_match",
  "detection_latency_ms",
  "timestamp",
  "validator_id",
  "node_id",
  "layer"

].join(",");


if (
  SECURITY_MODE &&
  !fs.existsSync(
    SECURITY_METRICS_FILE
  )
) {

  fs.writeFileSync(
    SECURITY_METRICS_FILE,
    SECURITY_CSV_HEADER + "\n"
  );

}


/* ============================================================
   CSV HELPERS
   ============================================================ */

function csvEscape(
  value
) {

  if (
    value === null ||
    value === undefined
  ) {

    return "";

  }

  const text =
    String(value);

  if (
    text.includes(",") ||
    text.includes('"') ||
    text.includes("\n")
  ) {

    return (
      '"' +
      text.replace(
        /"/g,
        '""'
      ) +
      '"'
    );

  }

  return text;

}


function appendMetrics(
  row
) {

  fs.appendFileSync(
    NODE_METRICS_FILE,
    row
      .map(csvEscape)
      .join(",") +
    "\n"
  );

}


/* ============================================================
   SECURITY METRIC
   ============================================================ */

function appendSecurityMetric(
  metric
) {

  if (
    !SECURITY_MODE
  ) {

    return;

  }

  const row = [

    metric.test_id || "",
    metric.run_id || "",
    metric.attack_type || "",
    metric.transaction_id || "",
    metric.camera_id || "",
    metric.sequence ?? "",
    metric.expected_result || "rejected",
    metric.actual_result || "rejected",
    metric.accepted ? 1 : 0,
    metric.detected ? 1 : 0,
    metric.rejection_reason || "",
    metric.signature_valid ?? "",
    metric.camera_authorized ?? "",
    metric.sequence_valid ?? "",
    metric.duplicate_tx ?? "",
    metric.offchain_hash_match ?? "",
    metric.detection_latency_ms ?? "",
    metric.timestamp ||
      new Date().toISOString(),
    VALIDATOR_ID,
    NODE_ID,
    metric.layer

  ];

  fs.appendFileSync(
    SECURITY_METRICS_FILE,
    row
      .map(csvEscape)
      .join(",") +
    "\n"
  );

}


/* ============================================================
   PQC VERIFICATION LIBRARY
   ============================================================ */

const uchar =
  ref.types.uchar;


const size_t =
  ref.types.size_t;


const ucharPtr =
  ref.refType(
    uchar
  );


let pqcLibrary =
  null;


try {

  pqcLibrary =
    ffi.Library(
      path.join(
        __dirname,
        "r1_sign_lib.so"
      ),
      {

        pqc_verify: [

          "int",

          [

            ucharPtr,
            size_t,

            ucharPtr,
            size_t,

            ucharPtr,

            "char"

          ]

        ]

      }
    );

  console.log(
    "PQC signature library loaded"
  );

} catch (
  error
) {

  console.error(
    "Failed to load r1_sign_lib.so:"
  );

  console.error(
    error.message
  );

  process.exit(
    1
  );

}


/* ============================================================
   ALGORITHM
   ============================================================ */

function getAlgorithmCode(
  payload
) {

  if (
    payload.algo_code !== undefined
  ) {

    return String(
      payload.algo_code
    );

  }

  if (
    payload.algo === "1" ||
    payload.algo === "2" ||
    payload.algo === "3"
  ) {

    return String(
      payload.algo
    );

  }

  if (
    typeof payload.algo ===
      "string" &&
    payload.algo
      .toLowerCase()
      .includes("falcon")
  ) {

    return "2";

  }

  if (
    typeof payload.algo ===
      "string" &&
    payload.algo
      .toLowerCase()
      .includes("mayo")
  ) {

    return "1";

  }

  if (
    typeof payload.algo ===
      "string" &&
    payload.algo
      .toLowerCase()
      .includes("sphincs")
  ) {

    return "3";

  }

  return DEFAULT_PQC_ALGO_CODE;

}


/* ============================================================
   NUMBER
   ============================================================ */

function numberOrNull(
  value
) {

  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {

    return null;

  }

  const n =
    Number(value);

  return Number.isFinite(n)
    ? n
    : null;

}


/* ============================================================
   SECURITY REJECTION
   ============================================================ */

function rejectSecurity(
  payload,
  detectionData,
  reason,
  fields = {}
) {

  const start =
    fields.startNs ||
    process.hrtime.bigint();


  const detectionLatency =
    Number(
      process.hrtime.bigint() -
      start
    ) / 1e6;


  appendSecurityMetric({

    test_id:
      payload.security_test_id ||
      SECURITY_TEST ||
      fields.test_id ||
      "",

    run_id:
      payload.security_run_id ||
      detectionData?.security_run_id ||
      fields.run_id ||
      "",

    attack_type:
      payload.attack_type ||
      detectionData?.attack_type ||
      fields.attack_type ||
      SECURITY_TEST,

    transaction_id:
      detectionData?.transaction_id ||
      payload.transaction_id ||
      "",

    camera_id:
      detectionData?.camera_id ||
      payload.camera_id ||
      "",

    sequence:
      detectionData?.sequence ??
      payload.sequence ??
      "",

    expected_result:
      "rejected",

    actual_result:
      "rejected",

    accepted:
      false,

    detected:
      true,

    rejection_reason:
      reason,

    signature_valid:
      fields.signature_valid ??
      "",

    camera_authorized:
      fields.camera_authorized ??
      "",

    sequence_valid:
      fields.sequence_valid ??
      "",

    duplicate_tx:
      fields.duplicate_tx ??
      "",

    offchain_hash_match:
      fields.offchain_hash_match ??
      "",

    detection_latency_ms:
      Number(
        detectionLatency.toFixed(3)
      ),

    layer:
      "MQTT_GATEWAY"

  });

}


/* ============================================================
   CAMERA AUTHORIZATION
   ============================================================ */

function cameraAuthorized(
  cameraId
) {

  return AUTHORIZED_CAMERAS.has(
    String(
      cameraId
    )
  );

}


/* ============================================================
   OUTER/SIGNED CONSISTENCY
   ============================================================ */

function checkOuterSignedConsistency(
  payload,
  signed
) {

  const pairs = [

    [
      "transaction_id",
      signed.transaction_id
    ],

    [
      "camera_id",
      signed.camera_id
    ],

    [
      "dataset",
      signed.dataset
    ],

    [
      "sequence",
      signed.sequence
    ]

  ];


  for (
    const [
      key,
      signedValue
    ]
    of pairs
  ) {

    if (
      payload[key] !== undefined &&
      signedValue !== undefined &&
      String(
        payload[key]
      ) !== String(
        signedValue
      )
    ) {

      return {

        ok: false,

        field:
          key

      };

    }

  }


  return {

    ok: true

  };

}


/* ============================================================
   MQTT CLIENT
   ============================================================ */

let client =
  null;


if (
  IS_MQTT_GATEWAY
) {

  client =
    mqtt.connect(
      MQTT_BROKER,
      {

        clientId:
          "yolochain-validator-" +
          VALIDATOR_ID +
          "-" +
          crypto
            .randomBytes(4)
            .toString("hex"),

        clean: true

      }
    );


  client.on(
    "connect",
    () => {

      console.log(
        "MQTT connected"
      );

      client.subscribe(
        MQTT_TOPICS,
        {
          qos: 1
        },
        error => {

          if (
            error
          ) {

            console.error(
              "MQTT subscribe error:",
              error.message
            );

            return;

          }

          console.log(
            "MQTT Gateway subscribed:"
          );

          for (
            const topic
            of MQTT_TOPICS
          ) {

            console.log(
              "  -",
              topic
            );

          }

          console.log(
            "Waiting for MQTT messages..."
          );

        }
      );

    }
  );


  client.on(
    "error",
    error => {

      console.error(
        "MQTT error:",
        error.message
      );

    }
  );

} else {

  console.log(
    "MQTT disabled for this validator."
  );

}


/* ============================================================
   MQTT MESSAGE
   ============================================================ */

if (
  IS_MQTT_GATEWAY
) {

  client.on(
    "message",
    (
      topic,
      message
    ) => {

      const nodeReceiveTimestampMs =
        Date.now();


      const nodeReceiveTimestamp =
        new Date(
          nodeReceiveTimestampMs
        ).toISOString();


      const nodeProcessingStart =
        process.hrtime.bigint();


      try {

        /* PAYLOAD */

        const payload =
          JSON.parse(
            message.toString(
              "utf8"
            )
          );


        /* CRYPTOGRAPHIC FIELDS */

        const messageB64 =
          payload.message_b64;


        const signatureB64 =
          payload.signature_b64 ||
          payload.signature;


        const publicKeyB64 =
          payload.public_key_b64 ||
          payload.public_key;


        if (
          !messageB64 ||
          !signatureB64 ||
          !publicKeyB64
        ) {

          rejectSecurity(
            payload,
            null,
            "missing_cryptographic_fields",
            {
              startNs:
                nodeProcessingStart
            }
          );

          console.error(
            "Missing cryptographic fields"
          );

          return;

        }


        const msgBuf =
          Buffer.from(
            messageB64,
            "base64"
          );


        const sigBuf =
          Buffer.from(
            signatureB64,
            "base64"
          );


        const pkBuf =
          Buffer.from(
            publicKeyB64,
            "base64"
          );


        /* ALGORITHM */

        const algoCode =
          getAlgorithmCode(
            payload
          );


        const algorithmName =
          payload.algo_name ||
          payload.algo ||
          (
            algoCode === "1"
              ? "mayo-1"
              : algoCode === "2"
                ? "falcon-512"
                : algoCode === "3"
                  ? "sphincs+-shake-256s-simple"
                  : "unknown"
          );


        /* ====================================================
           S2/S4:
           PQC SIGNATURE
           ==================================================== */

        const verifyStart =
          process.hrtime.bigint();


        const ret =
          pqcLibrary.pqc_verify(

            msgBuf,
            msgBuf.length,

            sigBuf,
            sigBuf.length,

            pkBuf,

            algoCode

          );


        const verifyEnd =
          process.hrtime.bigint();


        const verificationMs =
          Number(
            verifyEnd -
            verifyStart
          ) / 1e6;


        if (
          ret !== 0
        ) {

          console.error(
            `Signature INVALID | algorithm=${algoCode} | ret=${ret}`
          );


          rejectSecurity(
            payload,
            null,
            "invalid_pqc_signature",
            {

              startNs:
                nodeProcessingStart,

              signature_valid:
                false

            }
          );


          return;

        }


        /* SIGNED JSON */

        let detectionData;


        try {

          detectionData =
            JSON.parse(
              msgBuf.toString(
                "utf8"
              )
            );

        } catch (
          error
        ) {

          rejectSecurity(
            payload,
            null,
            "signed_payload_invalid_json",
            {

              startNs:
                nodeProcessingStart,

              signature_valid:
                true

            }
          );

          return;

        }


        /* ====================================================
           TRANSACTION ID
           ==================================================== */

        const transactionId =
          detectionData.transaction_id;


        /*
         * Do NOT generate a random transaction ID.
         *
         * The ID must be authenticated by the signed
         * payload.
         */

        if (
          !transactionId
        ) {

          rejectSecurity(
            payload,
            detectionData,
            "missing_signed_transaction_id",
            {

              startNs:
                nodeProcessingStart,

              signature_valid:
                true

            }
          );

          return;

        }


        /* ====================================================
           S4:
           OUTER/SIGNED CONSISTENCY
           ==================================================== */

        const consistency =
          checkOuterSignedConsistency(
            payload,
            detectionData
          );


        if (
          !consistency.ok
        ) {

          rejectSecurity(
            payload,
            detectionData,
            `outer_signed_mismatch:${consistency.field}`,
            {

              startNs:
                nodeProcessingStart,

              signature_valid:
                true

            }
          );

          return;

        }


        /* ====================================================
           S3:
           CAMERA AUTHORIZATION
           ==================================================== */

        const cameraId =
          detectionData.camera_id;


        const authorized =
          cameraAuthorized(
            cameraId
          );


        if (
          !authorized
        ) {

          rejectSecurity(
            payload,
            detectionData,
            "unauthorized_camera",
            {

              startNs:
                nodeProcessingStart,

              signature_valid:
                true,

              camera_authorized:
                false

            }
          );

          return;

        }


        /* ====================================================
           BASIC SEQUENCE VALIDATION
           ==================================================== */

        const sequence =
          detectionData.sequence;


        if (
          SECURITY_MODE &&
          !Number.isInteger(
            Number(sequence)
          )
        ) {

          rejectSecurity(
            payload,
            detectionData,
            "invalid_sequence",
            {

              startNs:
                nodeProcessingStart,

              signature_valid:
                true,

              camera_authorized:
                true,

              sequence_valid:
                false

            }
          );

          return;

        }


        /* ====================================================
           NORMALIZE DETECTIONS
           ==================================================== */

        const detections =
          Array.isArray(
            detectionData.detections
          )
            ? detectionData.detections
            : [];


        const detectionCount =
          detectionData.detection_count ??
          detections.length;


        /* IMAGE */

        const image =
          detectionData.image ||
          detectionData.frame_file ||
          null;


        const frameFile =
          detectionData.frame_file ||
          detectionData.image ||
          null;


        const frameId =
          detectionData.frame_id ??
          detectionData.image_index ??
          null;


        const imageIndex =
          detectionData.image_index ??
          detectionData.frame_id ??
          null;


        /* TIMESTAMP */

        const sourceTimestampMs =
          numberOrNull(
            detectionData.timestamp_ms
          ) ??
          numberOrNull(
            payload.timestamp_ms
          );


        /* ====================================================
           SOURCE TIMING
           ==================================================== */

        const sourceTiming =
          payload.timing ||
          detectionData.timing ||
          {};


        const pythonPipelineMs =
          sourceTiming.python_pipeline_ms ??
          sourceTiming.total_pipeline_ms ??
          "";


        const yoloInferenceMs =
          sourceTiming.yolo_inference_ms ??
          "";


        const postprocessingMs =
          sourceTiming.postprocessing_ms ??
          "";


        const jsonGenerationMs =
          sourceTiming.json_generation_ms ??
          "";


        const pqcSigningMs =
          sourceTiming.pqc_signing_ms ??
          "";


        const mqttTransmissionMs =
          sourceTiming.mqtt_transmission_ms ??
          "";


        /* MQTT -> NODE */

        let mqttToNodeMs =
          null;


        if (
          sourceTimestampMs !== null
        ) {

          mqttToNodeMs =
            nodeReceiveTimestampMs -
            sourceTimestampMs;


          if (
            mqttToNodeMs < 0 ||
            mqttToNodeMs >
              24 * 60 * 60 * 1000
          ) {

            mqttToNodeMs =
              null;

          }

        }


        /* ====================================================
           UNIFIED TX
           ==================================================== */

        const txBuildStart =
          process.hrtime.bigint();


        const blockchainTimestamp =
          Date.now();


        const tx = {

          id:
            transactionId,

          transaction_id:
            transactionId,

          tx_id:
            transactionId,

          blockchain_timestamp:
            blockchainTimestamp,

          blockchainTimestamp:
            blockchainTimestamp,

          validator_id:
            VALIDATOR_ID,

          node_id:
            NODE_ID,

          source_timestamp_ms:
            sourceTimestampMs,

          node_receive_timestamp_ms:
            nodeReceiveTimestampMs,

          camera_id:
            cameraId,

          dataset:
            detectionData.dataset ||
            payload.dataset ||
            null,

          sequence:
            sequence,

          image:
            image,

          image_index:
            imageIndex,

          frame_id:
            frameId,

          frame_file:
            frameFile,

          detection_timestamp:
            detectionData.timestamp ||
            null,

          detection_count:
            detectionCount,

          detections:
            detections,

          pqc: {

            algorithm:
              algorithmName,

            algorithm_code:
              algoCode,

            signature:
              signatureB64,

            publicKey:
              publicKeyB64,

            verification_ms:
              Number(
                verificationMs.toFixed(3)
              )

          },

          signed_payload:
            messageB64,

          source_timing:
            sourceTiming

        };


        /* ====================================================
           S5:
           OFF-CHAIN HASH
           ==================================================== */

        if (
          detectionData.offchain
        ) {

          tx.offchain = {

            media_sha256:
              detectionData
                .offchain
                .media_sha256 ||
              null,

            media_path:
              detectionData
                .offchain
                .media_path ||
              null,

            media_file:
              detectionData
                .offchain
                .media_file ||
              null

          };

        } else {

          tx.offchain = {

            media_sha256:
              detectionData.media_sha256 ||
              null,

            media_path:
              detectionData.media_path ||
              null,

            media_file:
              detectionData.media_file ||
              null

          };

        }


        const txBuildEnd =
          process.hrtime.bigint();


        const transactionProcessingMs =
          Number(
            txBuildEnd -
            txBuildStart
          ) / 1e6;


        const nodeProcessingEnd =
          process.hrtime.bigint();


        const nodeProcessingMs =
          Number(
            nodeProcessingEnd -
            nodeProcessingStart
          ) / 1e6;


        /* MODEL */

        const modelName =
          detectionData.model ||
          payload.model ||
          sourceTiming.model ||
          "";


        const imageSize =
          detectionData.img_size ??
          payload.img_size ??
          sourceTiming.img_size ??
          "";


        const confidenceThreshold =
          detectionData.conf_threshold ??
          payload.conf_threshold ??
          sourceTiming.conf_threshold ??
          "";


        const iouThreshold =
          detectionData.iou_threshold ??
          payload.iou_threshold ??
          sourceTiming.iou_threshold ??
          "";


        /* ====================================================
           SUBMIT
           ==================================================== */

        const submitStart =
          process.hrtime.bigint();


        const submitResult =
          p2p.submitTx(
            tx
          );


        const submitEnd =
          process.hrtime.bigint();


        const submitCallMs =
          Number(
            submitEnd -
            submitStart
          ) / 1e6;


        /*
         * S1:
         * submitTx() may reject duplicate transaction ID
         * or stale sequence.
         */

        if (
          !submitResult ||
          submitResult.accepted !== true
        ) {

          rejectSecurity(
            payload,
            detectionData,
            submitResult?.reason ||
              "p2p_transaction_rejected",
            {

              startNs:
                nodeProcessingStart,

              signature_valid:
                true,

              camera_authorized:
                true,

              sequence_valid:
                submitResult
                  ?.security
                  ?.sequence_valid ??
                "",

              duplicate_tx:
                submitResult
                  ?.reason ===
                  "duplicate_tx_id"

            }
          );


          console.log(
            "P2P rejected transaction:",
            submitResult?.reason
          );


          return;

        }


        /* ====================================================
           SECURITY SUCCESS
           ==================================================== */

        if (
          SECURITY_MODE &&
          payload.security_test_id
        ) {

          appendSecurityMetric({

            test_id:
              payload.security_test_id,

            run_id:
              payload.security_run_id ||
              "",

            attack_type:
              payload.attack_type ||
              SECURITY_TEST,

            transaction_id:
              tx.id,

            camera_id:
              tx.camera_id,

            sequence:
              tx.sequence,

            expected_result:
              payload.expected_result ||
              "accepted",

            actual_result:
              "accepted",

            accepted:
              true,

            detected:
              false,

            rejection_reason:
              "",

            signature_valid:
              true,

            camera_authorized:
              true,

            sequence_valid:
              true,

            duplicate_tx:
              false,

            offchain_hash_match:
              "",

            detection_latency_ms:
              Number(
                (
                  Number(
                    process.hrtime.bigint() -
                    nodeProcessingStart
                  ) /
                  1e6
                ).toFixed(3)
              ),

            layer:
              "MQTT_GATEWAY"

          });

        }


        /* ====================================================
           NODE METRICS
           ==================================================== */

        appendMetrics([

          VALIDATOR_ID,

          NODE_ID,

          nodeReceiveTimestamp,

          nodeReceiveTimestampMs,

          topic,

          tx.id,

          sourceTimestampMs,

          tx.camera_id,

          tx.dataset,

          tx.sequence,

          tx.image,

          tx.image_index,

          tx.frame_id,

          tx.frame_file,

          tx.detection_count,

          algorithmName,

          algoCode,

          Number(
            verificationMs.toFixed(3)
          ),

          Number(
            transactionProcessingMs.toFixed(3)
          ),

          Number(
            nodeProcessingMs.toFixed(3)
          ),

          Number(
            submitCallMs.toFixed(3)
          ),

          mqttToNodeMs !== null
            ? Number(
                mqttToNodeMs.toFixed(3)
              )
            : "",

          pythonPipelineMs,

          yoloInferenceMs,

          postprocessingMs,

          jsonGenerationMs,

          pqcSigningMs,

          mqttTransmissionMs,

          modelName,

          imageSize,

          confidenceThreshold,

          iouThreshold

        ]);


        console.log(
          "\nTransaction accepted by gateway/P2P"
        );

        console.log(
          "TX:",
          tx.id
        );

        console.log(
          "Camera:",
          tx.camera_id
        );

        console.log(
          "Sequence:",
          tx.sequence
        );

        console.log(
          "PQC verification:",
          verificationMs.toFixed(3),
          "ms"
        );

        console.log(
          "P2P submit:",
          submitCallMs.toFixed(3),
          "ms"
        );


      } catch (
        error
      ) {

        console.error(
          "MQTT processing error:",
          error.message
        );

        console.error(
          error.stack
        );

      }

    }
  );

}


/* ============================================================
   SHUTDOWN
   ============================================================ */

function shutdown() {

  console.log(
    "\nShutting down..."
  );


  if (
    !client
  ) {

    process.exit(
      0
    );

    return;

  }


  try {

    client.end(
      true,
      () => {

        console.log(
          "MQTT disconnected"
        );

        process.exit(
          0
        );

      }
    );

  } catch (
    error
  ) {

    process.exit(
      0
    );

  }

}


process.on(
  "SIGINT",
  shutdown
);


process.on(
  "SIGTERM",
  shutdown
);


if (
  IS_MQTT_GATEWAY
) {

  console.log(
    "Waiting for MQTT messages..."
  );

} else {

  console.log(
    "Waiting for P2P/PBFT transactions..."
  );

}
