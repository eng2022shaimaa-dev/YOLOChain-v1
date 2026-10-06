#!/usr/bin/env node

"use strict";

const crypto = require("crypto");
const ffi = require("ffi-napi");
const ref = require("ref-napi");
const mqtt = require("mqtt");
const fs = require("fs");
const path = require("path");

/*
 * ============================================================
 * YOLOChain
 * Experiment D
 *
 * MQTT Gateway + PQC Signature Verification
 * + P2P + PQC KEM + AES-256-GCM + PBFT + Blockchain
 *
 * Architecture:
 *
 *   Camera / Python
 *          |
 *          | MQTT
 *          v
 *   Validator 1
 *      MQTT Gateway
 *          |
 *          | P2P secure channel
 *          v
 *   Validator 2
 *   Validator 3
 *   Validator 4
 *          |
 *          v
 *        PBFT
 *          |
 *          v
 *   Local blockchain
 *
 * IMPORTANT:
 *
 * Only Validator 1 subscribes to MQTT.
 * Validators 2-4 participate through P2P/PBFT.
 *
 * PQC signature verification is performed here using
 * r1_sign_lib.so and pqc_verify().
 * ============================================================
 */


/* ============================================================
   CONFIGURATION
   ============================================================ */

const MQTT_BROKER = "mqtt://localhost:1883";

const MQTT_TOPICS = [
  "pqc/handshake",
  "pqc1/handshake"
];


/*
 * Validator identity.
 *
 * Example:
 *
 * VALIDATOR_ID=1 NODE_ID=validator_1 node r_mqtt_app_D.js
 *
 * VALIDATOR_ID=2 NODE_ID=validator_2 node r_mqtt_app_D.js
 */

const VALIDATOR_ID =
  String(
    process.env.VALIDATOR_ID || "1"
  );

const NODE_ID =
  process.env.NODE_ID ||
  `validator_${VALIDATOR_ID}`;


/*
 * Only Validator 1 is the MQTT gateway.
 */

const IS_MQTT_GATEWAY =
  VALIDATOR_ID === "1";


/*
 * Default PQC signature algorithm.
 *
 * 1 = MAYO-1
 * 2 = Falcon-512
 * 3 = SPHINCS+-SHAKE-256s-simple
 *
 * Current experiment:
 *
 * 2 = Falcon-512
 */

const DEFAULT_PQC_ALGO_CODE = "2";


/* ============================================================
   PATHS
   ============================================================ */

const ROOT_RESULTS_DIR =
  path.join(
    __dirname,
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


/*
 * Create local directories.
 */

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


const NODE_METRICS_FILE =
  path.join(
    RESULTS_DIR,
    "node_metrics.csv"
  );


/* ============================================================
   STARTUP INFORMATION
   ============================================================ */

console.log(
  "\n============================================================"
);

console.log(
  "YOLOChain - Experiment D"
);

console.log(
  "MQTT + PQC Signature Verification + P2P + PBFT + Blockchain"
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
  "Results dir  :",
  RESULTS_DIR
);

console.log(
  "Metrics file :",
  NODE_METRICS_FILE
);

console.log(
  "============================================================\n"
);


/* ============================================================
   LOAD P2P / BLOCKCHAIN MODULE
   ============================================================ */

/*
 * IMPORTANT:
 *
 * Experiment D must use p2p_blockchain_D.js.
 *
 * Do NOT use p2p_blockchain2.js here.
 */

const p2p =
  require(
    "./p2p_blockchain_D_nv"
  );


/* ============================================================
   CSV HEADER
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


/* ============================================================
   CSV INITIALIZATION
   ============================================================ */

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
   CSV HELPER
   ============================================================ */

function csvEscape(value) {

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


function appendMetrics(row) {

  const values =
    row.map(
      csvEscape
    );

  fs.appendFileSync(
    NODE_METRICS_FILE,
    values.join(",") + "\n"
  );
}


/* ============================================================
   PQC SIGNATURE VERIFICATION LIBRARY
   ============================================================ */

const uchar =
  ref.types.uchar;

const size_t =
  ref.types.size_t;

const ucharPtr =
  ref.refType(
    uchar
  );


/*
 * IMPORTANT:
 *
 * This ABI is preserved exactly from the working
 * r_mqtt_app.js supplied by the user.
 *
 * C/C++ interface:
 *
 * int pqc_verify(
 *     unsigned char *message,
 *     size_t message_len,
 *     unsigned char *signature,
 *     size_t signature_len,
 *     unsigned char *public_key,
 *     char algo_code
 * );
 */

let pqcLibrary = null;

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
    "✅ PQC signature library loaded:"
  );

  console.log(
    "   r1_sign_lib.so"
  );

} catch (error) {

  console.error(
    "❌ Failed to load r1_sign_lib.so"
  );

  console.error(
    error.message
  );

  process.exit(
    1
  );
}


/* ============================================================
   ALGORITHM CODE
   ============================================================ */

function getAlgorithmCode(
  payload
) {

  /*
   * New unified format.
   */

  if (
    payload.algo_code !== undefined
  ) {

    return String(
      payload.algo_code
    );
  }


  /*
   * Old numeric format.
   */

  if (
    payload.algo === "1" ||
    payload.algo === "2" ||
    payload.algo === "3"
  ) {

    return String(
      payload.algo
    );
  }


  /*
   * Old Falcon format.
   */

  if (
    typeof payload.algo === "string" &&
    payload.algo
      .toLowerCase()
      .includes("falcon")
  ) {

    return "2";
  }


  /*
   * MAYO.
   */

  if (
    typeof payload.algo === "string" &&
    payload.algo
      .toLowerCase()
      .includes("mayo")
  ) {

    return "1";
  }


  /*
   * SPHINCS+.
   */

  if (
    typeof payload.algo === "string" &&
    payload.algo
      .toLowerCase()
      .includes("sphincs")
  ) {

    return "3";
  }


  return DEFAULT_PQC_ALGO_CODE;
}


/* ============================================================
   SAFE NUMBER HELPER
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
   MQTT CLIENT
   ============================================================ */

let client = null;


/*
 * Only Validator 1 connects/subscribes to MQTT.
 *
 * Validators 2-4 are P2P/PBFT nodes.
 */

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


  /* ==========================================================
     MQTT CONNECT
     ========================================================== */

  client.on(
    "connect",
    () => {

      console.log(
        "🟢 MQTT connected"
      );

      client.subscribe(
        MQTT_TOPICS,
        {
          qos: 1
        },
        error => {

          if (error) {

            console.error(
              "❌ MQTT subscribe error:",
              error.message
            );

            return;
          }


          console.log(
            "📡 MQTT Gateway subscribed:"
          );


          for (
            const topic of MQTT_TOPICS
          ) {

            console.log(
              "   -",
              topic
            );
          }


          console.log(
            "\n📊 Node metrics file:"
          );

          console.log(
            NODE_METRICS_FILE
          );

          console.log(
            "\n🚀 Validator 1 is ready to receive"
          );

          console.log(
            "   MQTT application transactions.\n"
          );
        }
      );
    }
  );


  /* ==========================================================
     MQTT ERROR
     ========================================================== */

  client.on(
    "error",
    error => {

      console.error(
        "❌ MQTT error:",
        error.message
      );
    }
  );

} else {

  /*
   * Validators 2-4:
   *
   * No MQTT connection.
   * They participate through P2P/PBFT.
   */

  console.log(
    "ℹ️ MQTT disabled for this validator."
  );

  console.log(
    "ℹ️ This validator participates through P2P/PBFT."
  );

}


/* ============================================================
   MQTT MESSAGE HANDLER
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

      /*
       * This timestamp represents the time at which
       * Validator 1 receives the MQTT message.
       */

      const nodeReceiveTimestampMs =
        Date.now();


      const nodeReceiveTimestamp =
        new Date(
          nodeReceiveTimestampMs
        ).toISOString();


      const nodeProcessingStart =
        process.hrtime.bigint();


      try {

        /* ====================================================
           MQTT PAYLOAD
           ==================================================== */

        const payload =
          JSON.parse(
            message.toString(
              "utf8"
            )
          );


        /* ====================================================
           CRYPTOGRAPHIC FIELDS
           ==================================================== */

        /*
         * Supported formats:
         *
         * message_b64
         * signature_b64
         * public_key_b64
         *
         * and older names.
         */

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

          console.error(
            "❌ Missing cryptographic fields"
          );

          console.log(
            "Received keys:",
            Object.keys(payload)
          );

          return;
        }


        /* ====================================================
           BASE64 DECODE
           ==================================================== */

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


        /* ====================================================
           PQC ALGORITHM
           ==================================================== */

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
           PQC SIGNATURE VERIFICATION
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


        /*
         * IMPORTANT:
         *
         * ret == 0 means valid according to the working
         * r1_sign_lib.so interface supplied by the user.
         */

        if (
          ret !== 0
        ) {

          console.error(
            `❌ Signature INVALID | algorithm=${algoCode} | ret=${ret}`
          );

          return;
        }


        console.log(
          `\n✅ PQC signature VALID | algorithm=${algoCode}`
        );

        console.log(
          "   Verification:",
          verificationMs.toFixed(3),
          "ms"
        );


        /* ====================================================
           SIGNED DETECTION DATA
           ==================================================== */

        let detectionData;


        try {

          detectionData =
            JSON.parse(
              msgBuf.toString(
                "utf8"
              )
            );

        } catch (error) {

          console.error(
            "❌ Signed message is not valid JSON"
          );

          console.error(
            error.message
          );

          return;
        }


        /* ====================================================
           TRANSACTION ID
           ==================================================== */

        /*
         * transaction_id is expected to originate from Python
         * and to be included inside the signed message.
         *
         * It is preserved through:
         *
         * Python
         *   ->
         * MQTT
         *   ->
         * Validator 1
         *   ->
         * P2P
         *   ->
         * PBFT
         *   ->
         * Blockchain
         */

        const transactionId =
          detectionData.transaction_id ||
          payload.transaction_id ||
          crypto
            .randomBytes(16)
            .toString("hex");


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


        /* ====================================================
           IMAGE / FRAME
           ==================================================== */

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


        /* ====================================================
           SOURCE TIMESTAMP
           ==================================================== */

        const sourceTimestampMs =
          numberOrNull(
            detectionData.timestamp_ms
          ) ??
          numberOrNull(
            payload.timestamp_ms
          );


        /* ====================================================
           DISPLAY
           ==================================================== */

        console.log(
          "📷 Camera ID :",
          detectionData.camera_id
        );

        console.log(
          "📚 Dataset   :",
          detectionData.dataset ||
          "unknown"
        );

        console.log(
          "🎞️ Sequence  :",
          detectionData.sequence ||
          "N/A"
        );

        console.log(
          "🆔 TX ID     :",
          transactionId
        );

        console.log(
          "🖼️ Image     :",
          image
        );

        console.log(
          "🔢 Frame     :",
          frameId
        );

        console.log(
          "🎯 Detections:",
          detectionCount
        );

        console.log(
          "🔐 PQC verify:",
          verificationMs.toFixed(3),
          "ms"
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


        /* ====================================================
           MQTT -> NODE LATENCY
           ==================================================== */

        let mqttToNodeMs =
          null;


        if (
          sourceTimestampMs !== null
        ) {

          mqttToNodeMs =
            nodeReceiveTimestampMs -
            sourceTimestampMs;


          /*
           * Ignore obviously invalid values caused by
           * clock differences or malformed timestamps.
           */

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
           CREATE UNIFIED TRANSACTION
           ==================================================== */

        const txBuildStart =
          process.hrtime.bigint();


        const blockchainTimestamp =
          Date.now();


        const tx = {

          /*
           * CRITICAL:
           *
           * p2p_blockchain_D.js uses tx.id.
           *
           * Preserve the Python transaction ID.
           */

          id:
            transactionId,


          transaction_id:
            transactionId,


          tx_id:
            transactionId,


          /*
           * Blockchain timestamp.
           */

          blockchain_timestamp:
            blockchainTimestamp,


          blockchainTimestamp:
            blockchainTimestamp,


          /*
           * Validator information.
           */

          validator_id:
            VALIDATOR_ID,


          node_id:
            NODE_ID,


          /* ================================================
             SOURCE TIMING
             ================================================ */

          source_timestamp_ms:
            sourceTimestampMs,


          node_receive_timestamp_ms:
            nodeReceiveTimestampMs,


          /* ================================================
             CAMERA
             ================================================ */

          camera_id:
            detectionData.camera_id ||
            payload.camera_id ||
            null,


          /* ================================================
             DATASET
             ================================================ */

          dataset:
            detectionData.dataset ||
            payload.dataset ||
            null,


          sequence:
            detectionData.sequence ??
            null,


          /* ================================================
             IMAGE / FRAME
             ================================================ */

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


          /* ================================================
             OBJECT DETECTION
             ================================================ */

          detection_count:
            detectionCount,


          detections:
            detections,


          /* ================================================
             PQC
             ================================================ */

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


          /* ================================================
             ORIGINAL SIGNED PAYLOAD
             ================================================ */

          signed_payload:
            messageB64,


          /* ================================================
             SOURCE TIMING
             ================================================ */

          source_timing:
            sourceTiming

        };


        const txBuildEnd =
          process.hrtime.bigint();


        const transactionProcessingMs =
          Number(
            txBuildEnd -
            txBuildStart
          ) / 1e6;


        /* ====================================================
           NODE PROCESSING TIME
           ==================================================== */

        const nodeProcessingEnd =
          process.hrtime.bigint();


        const nodeProcessingMs =
          Number(
            nodeProcessingEnd -
            nodeProcessingStart
          ) / 1e6;


        /* ====================================================
           MODEL / EXPERIMENT PARAMETERS
           ==================================================== */

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
           UNIFIED TRANSACTION DISPLAY
           ==================================================== */

        console.log(
          "\n📦 UNIFIED TRANSACTION"
        );

        console.log(
          "TX ID       :",
          tx.id
        );

        console.log(
          "Camera      :",
          tx.camera_id
        );

        console.log(
          "Dataset     :",
          tx.dataset
        );

        console.log(
          "Sequence    :",
          tx.sequence
        );

        console.log(
          "Frame/Image :",
          tx.frame_id ??
          tx.image_index
        );

        console.log(
          "Objects     :",
          tx.detection_count
        );

        console.log(
          "PQC verify  :",
          verificationMs.toFixed(3),
          "ms"
        );

        console.log(
          "MQTT->Node  :",
          mqttToNodeMs !== null
            ? mqttToNodeMs.toFixed(3) +
              " ms"
            : "N/A"
        );

        console.log(
          "TX process  :",
          transactionProcessingMs.toFixed(3),
          "ms"
        );

        console.log(
          "Node total  :",
          nodeProcessingMs.toFixed(3),
          "ms"
        );


        /* ====================================================
           SEND TO P2P / PBFT
           ==================================================== */

        const submitStart =
          process.hrtime.bigint();


        /*
         * Validator 1 is the application-originating
         * validator.
         *
         * p2p_blockchain_D.js should:
         *
         *   - preserve tx.id
         *   - assign primary_id
         *   - record submission timestamp
         *   - broadcast TX
         *   - start PBFT locally
         */

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


        console.log(
          "🚀 Submitted to P2P/PBFT"
        );

        console.log(
          "P2P submit call:",
          submitCallMs.toFixed(3),
          "ms"
        );


        /* ====================================================
           NODE METRICS CSV
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
          "📊 Node metrics saved"
        );

        console.log(
          "   ->",
          NODE_METRICS_FILE
        );


      } catch (error) {

        console.error(
          "❌ MQTT processing error:",
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
   GRACEFUL SHUTDOWN
   ============================================================ */

function shutdown() {

  console.log(
    "\n🛑 Shutting down..."
  );


  /*
   * Non-gateway validators do not have an MQTT client.
   */

  if (
    !client
  ) {

    console.log(
      "ℹ️ MQTT client not active."
    );

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
          "🔌 MQTT disconnected"
        );

        process.exit(
          0
        );

      }
    );

  } catch (error) {

    console.error(
      "Shutdown error:",
      error.message
    );

    process.exit(
      0
    );
  }
}


/* ============================================================
   SIGNAL HANDLERS
   ============================================================ */

process.on(
  "SIGINT",
  shutdown
);

process.on(
  "SIGTERM",
  shutdown
);


/* ============================================================
   READY MESSAGE
   ============================================================ */

if (
  IS_MQTT_GATEWAY
) {

  console.log(
    "⏳ Waiting for MQTT messages..."
  );

} else {

  console.log(
    "⏳ Waiting for P2P/PBFT transactions..."
  );

}
