/*****************************************************************
 * YOLOChain
 * Experiment D
 *
 * Unified P2P + PQC KEM + AES-256-GCM + TX + PBFT + Blockchain
 *
 * SECURITY-EXTENDED VERSION
 *
 * Normal Experiment D:
 *   unchanged when SECURITY_MODE=0
 *
 * Security experiments:
 *
 *   S1 - Replay attack
 *   S2 - Modified metadata
 *   S3 - Unauthorized / fake camera
 *   S4 - MITM / ciphertext tampering
 *   S5 - Off-chain integrity is handled by the MQTT/Python layer
 *
 *****************************************************************/

"use strict";

const crypto = require("crypto");
const Swarm = require("discovery-swarm");
const defaults = require("dat-swarm-defaults");
const getPort = require("port-get");
const ffi = require("ffi-napi");
const ref = require("ref-napi");
const fs = require("fs");
const path = require("path");


/* ============================================================
   VALIDATOR CONFIGURATION
   ============================================================ */

const VALIDATOR_ID =
  String(
    process.env.VALIDATOR_ID || "1"
  );

const NODE_ID =
  String(
    process.env.NODE_ID ||
    `validator_${VALIDATOR_ID}`
  );


/* ============================================================
   SECURITY CONFIGURATION
   ============================================================ */

const SECURITY_MODE =
  String(
    process.env.SECURITY_MODE || "0"
  ) === "1";


const SECURITY_TEST =
  String(
    process.env.SECURITY_TEST || ""
  ).toUpperCase();


/*
 * Example:
 *
 * AUTHORIZED_CAMERAS=camera_01,camera_02,camera_03,camera_04
 *
 * If not supplied, camera_01 is allowed.
 *
 * This is intentionally explicit so that S3 can test
 * an unauthorized camera ID.
 */

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


/*
 * In security mode the sequence number must be numeric.
 */

const REQUIRE_NUMERIC_SEQUENCE =
  SECURITY_MODE;


/*
 * Optional P2P tampering.
 *
 * SECURITY_TAMPER_P2P_ONCE=1
 *
 * One encrypted DATA packet is deliberately corrupted.
 *
 * This is used only for S4.
 */

let tamperP2POnce =
  String(
    process.env.SECURITY_TAMPER_P2P_ONCE ||
    "0"
  ) === "1";


/* ============================================================
   RESULTS
   ============================================================ */

const ROOT_RESULTS_NAME =
  process.env.RESULTS_ROOT ||
  "results_D";


const ROOT_RESULTS_DIR =
  path.join(
    __dirname,
    ROOT_RESULTS_NAME
  );


const VALIDATOR_DIR =
  path.join(
    ROOT_RESULTS_DIR,
    `validator_${VALIDATOR_ID}`
  );


const DATA_DIR =
  path.join(
    VALIDATOR_DIR,
    "data"
  );


const RESULTS_DIR =
  path.join(
    VALIDATOR_DIR,
    "results"
  );


const CHAIN_FILE =
  path.join(
    DATA_DIR,
    "blockchain.json"
  );


const PBFT_METRICS_FILE =
  path.join(
    RESULTS_DIR,
    "pbft_metrics.csv"
  );


/*
 * Security results are deliberately outside the normal
 * validator metrics.
 */

const SECURITY_DIR =
  path.join(
    ROOT_RESULTS_DIR,
    "security"
  );


const SECURITY_METRICS_FILE =
  path.join(
    SECURITY_DIR,
    "security_metrics.csv"
  );


const SECURITY_SEQUENCE_FILE =
  path.join(
    SECURITY_DIR,
    "sequence_state.json"
  );


fs.mkdirSync(
  DATA_DIR,
  {
    recursive: true
  }
);


fs.mkdirSync(
  RESULTS_DIR,
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


/* ============================================================
   STARTUP
   ============================================================ */

console.log(
  "============================================================"
);

console.log(
  "YOLOChain Experiment D"
);

console.log(
  "Validator ID:",
  VALIDATOR_ID
);

console.log(
  "Node ID:",
  NODE_ID
);

console.log(
  "Blockchain:",
  CHAIN_FILE
);

console.log(
  "PBFT metrics:",
  PBFT_METRICS_FILE
);

console.log(
  "Security mode:",
  SECURITY_MODE
    ? "ON"
    : "OFF"
);

if (
  SECURITY_MODE
) {

  console.log(
    "Security test:",
    SECURITY_TEST || "not specified"
  );

  console.log(
    "Authorized cameras:",
    Array.from(
      AUTHORIZED_CAMERAS
    ).join(", ")
  );

  console.log(
    "Security metrics:",
    SECURITY_METRICS_FILE
  );

}

console.log(
  "============================================================"
);


/* ============================================================
   NETWORK
   ============================================================ */

const NETWORK_NAME =
  "myBlockchain";


const KEM_ALGO =
  "1";


/* ============================================================
   PBFT
   ============================================================ */

const N = 4;

const F =
  Math.floor(
    (N - 1) / 3
  );

const QUORUM =
  2 * F + 1;


/* ============================================================
   PBFT CSV
   ============================================================ */

const PBFT_CSV_HEADER = [

  "validator_id",
  "node_id",
  "commit_timestamp",
  "block_index",
  "tx_id",
  "digest",
  "primary_id",
  "camera_id",
  "dataset",
  "sequence",
  "frame_id",
  "image_index",
  "detection_count",
  "tx_submission_timestamp",
  "pbft_start_timestamp",
  "preprepare_timestamp",
  "prepare_quorum_timestamp",
  "commit_start_timestamp",
  "commit_quorum_timestamp",
  "block_append_timestamp",
  "pbft_preprepare_ms",
  "pbft_prepare_ms",
  "pbft_commit_phase_ms",
  "pbft_latency_ms",
  "transaction_commit_latency_ms",
  "block_write_ms",
  "total_consensus_to_disk_ms",
  "committed_tps"

].join(",");


if (
  !fs.existsSync(
    PBFT_METRICS_FILE
  )
) {

  fs.writeFileSync(
    PBFT_METRICS_FILE,
    PBFT_CSV_HEADER + "\n"
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
   CSV
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


function appendPBFTMetrics(
  row
) {

  fs.appendFileSync(
    PBFT_METRICS_FILE,
    row
      .map(csvEscape)
      .join(",") +
    "\n"
  );

}


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
    metric.expected_result || "",
    metric.actual_result || "",
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
   TIMER
   ============================================================ */

function nowNs() {

  return process.hrtime.bigint();

}


function elapsedMs(
  startNs,
  endNs
) {

  if (
    startNs === null ||
    startNs === undefined ||
    endNs === null ||
    endNs === undefined
  ) {

    return null;

  }

  return Number(
    endNs - startNs
  ) / 1e6;

}


function roundMs(
  value
) {

  if (
    value === null ||
    value === undefined
  ) {

    return "";

  }

  return Number(
    value.toFixed(3)
  );

}


/* ============================================================
   PQC KEM
   ============================================================ */

const uint8Ptr =
  ref.refType(
    ref.types.uint8
  );


const pqc =
  ffi.Library(
    "./r1_pqc_kem_lib.so",
    {

      pqc_kem_keypair: [

        "int",

        [
          "char",
          uint8Ptr,
          "size_t*",
          uint8Ptr,
          "size_t*"
        ]

      ],

      pqc_kem_encaps: [

        "int",

        [
          "char",
          uint8Ptr,
          uint8Ptr,
          "size_t*",
          uint8Ptr,
          "size_t*"
        ]

      ],

      pqc_kem_decaps: [

        "int",

        [
          "char",
          uint8Ptr,
          uint8Ptr,
          uint8Ptr,
          "size_t*"
        ]

      ]

    }
  );


/* ============================================================
   AES-256-GCM
   ============================================================ */

function aesEncrypt(
  key,
  data
) {

  const iv =
    crypto.randomBytes(
      12
    );

  const cipher =
    crypto.createCipheriv(
      "aes-256-gcm",
      key,
      iv
    );

  const encrypted =
    Buffer.concat([
      cipher.update(data),
      cipher.final()
    ]);

  return {

    iv:
      iv.toString("base64"),

    tag:
      cipher
        .getAuthTag()
        .toString("base64"),

    data:
      encrypted.toString("base64")

  };

}


function aesDecrypt(
  key,
  payload
) {

  const decipher =
    crypto.createDecipheriv(
      "aes-256-gcm",
      key,
      Buffer.from(
        payload.iv,
        "base64"
      )
    );

  decipher.setAuthTag(
    Buffer.from(
      payload.tag,
      "base64"
    )
  );

  return Buffer.concat([

    decipher.update(
      Buffer.from(
        payload.data,
        "base64"
      )
    ),

    decipher.final()

  ]);

}


/* ============================================================
   PEER STATE
   ============================================================ */

const STATE = {

  INIT: "INIT",

  HELLO_SENT:
    "HELLO_SENT",

  SECURE:
    "SECURE"

};


/* ============================================================
   PEER ID
   ============================================================ */

const myPeerId =
  crypto.randomBytes(
    32
  );


const myPeerIdHex =
  myPeerId.toString(
    "hex"
  );


console.log(
  "My Peer ID:",
  myPeerIdHex
);


/* ============================================================
   KEM KEYPAIR
   ============================================================ */

const pkPtr =
  ref.alloc(
    uint8Ptr
  );

const pkLen =
  ref.alloc(
    "size_t"
  );

const skPtr =
  ref.alloc(
    uint8Ptr
  );

const skLen =
  ref.alloc(
    "size_t"
  );


const keypairResult =
  pqc.pqc_kem_keypair(
    KEM_ALGO,
    pkPtr,
    pkLen,
    skPtr,
    skLen
  );


if (
  keypairResult !== 0
) {

  throw new Error(
    `PQC KEM keypair failed: ${keypairResult}`
  );

}


const publicKey =
  ref.reinterpret(
    pkPtr.deref(),
    pkLen.deref()
  );


const secretKey =
  ref.reinterpret(
    skPtr.deref(),
    skLen.deref()
  );


/* ============================================================
   GLOBAL STATE
   ============================================================ */

const peers =
  new Map();

const txPool =
  new Map();

const seenTx =
  new Set();

const txByDigest =
  new Map();

const pbftMetrics =
  new Map();

const canonicalMetricsWritten =
  new Set();

const commitHistory =
  [];


/*
 * Highest accepted sequence per camera.
 *
 * This is deliberately independent from seenTx.
 *
 * Therefore:
 *
 * TX-A / camera_01 / seq=10
 *
 * followed by
 *
 * TX-B / camera_01 / seq=10
 *
 * is rejected even though TX-B has a new transaction ID.
 */

const highestSequenceByCamera =
  new Map();


/* ============================================================
   LOAD PERSISTED SECURITY SEQUENCE STATE
   ============================================================ */

function loadSecuritySequenceState() {

  if (
    !SECURITY_MODE
  ) {

    return;

  }

  if (
    !fs.existsSync(
      SECURITY_SEQUENCE_FILE
    )
  ) {

    return;

  }

  try {

    const data =
      JSON.parse(
        fs.readFileSync(
          SECURITY_SEQUENCE_FILE,
          "utf8"
        )
      );

    for (
      const [
        camera,
        sequence
      ]
      of Object.entries(
        data
      )
    ) {

      const n =
        Number(sequence);

      if (
        Number.isFinite(n)
      ) {

        highestSequenceByCamera.set(
          camera,
          n
        );

      }

    }

  } catch (error) {

    console.error(
      "Security sequence-state load error:",
      error.message
    );

  }

}


function saveSecuritySequenceState() {

  if (
    !SECURITY_MODE
  ) {

    return;

  }

  const obj = {};

  for (
    const [
      camera,
      sequence
    ]
    of highestSequenceByCamera
  ) {

    obj[camera] =
      sequence;

  }

  fs.writeFileSync(
    SECURITY_SEQUENCE_FILE,
    JSON.stringify(
      obj,
      null,
      2
    ),
    "utf8"
  );

}


/* ============================================================
   BLOCKCHAIN
   ============================================================ */

function loadBlockchain() {

  if (
    !fs.existsSync(
      CHAIN_FILE
    )
  ) {

    return [];

  }

  try {

    const chain =
      JSON.parse(
        fs.readFileSync(
          CHAIN_FILE,
          "utf8"
        )
      );

    /*
     * Reconstruct sequence state in security mode.
     */

    if (
      SECURITY_MODE
    ) {

      for (
        const block of chain
      ) {

        const camera =
          block.camera_id;

        const sequence =
          Number(
            block.sequence
          );

        if (
          camera &&
          Number.isFinite(
            sequence
          )
        ) {

          const previous =
            highestSequenceByCamera.get(
              String(camera)
            );

          if (
            previous === undefined ||
            sequence > previous
          ) {

            highestSequenceByCamera.set(
              String(camera),
              sequence
            );

          }

        }

      }

    }

    return chain;

  } catch (error) {

    console.error(
      "Blockchain load error:",
      error.message
    );

    return [];

  }

}


const blockchain =
  loadBlockchain();


loadSecuritySequenceState();


function saveBlockchain() {

  const writeStart =
    nowNs();

  try {

    fs.writeFileSync(
      CHAIN_FILE,
      JSON.stringify(
        blockchain,
        null,
        2
      ),
      "utf8"
    );

    return elapsedMs(
      writeStart,
      nowNs()
    );

  } catch (error) {

    console.error(
      "Blockchain save error:",
      error.message
    );

    return null;

  }

}


/* ============================================================
   PBFT
   ============================================================ */

const pbft = {

  preprepares:
    new Set(),

  prepares:
    new Map(),

  commits:
    new Map(),

  committed:
    new Set()

};


/* ============================================================
   SECURITY VALIDATION
   ============================================================ */

function validateSecurityTransaction(
  tx
) {

  if (
    !SECURITY_MODE
  ) {

    return {

      ok: true

    };

  }


  const cameraId =
    tx.camera_id !== undefined &&
    tx.camera_id !== null
      ? String(tx.camera_id)
      : "";


  if (
    !cameraId
  ) {

    return {

      ok: false,

      reason:
        "missing_camera_id",

      camera_authorized:
        false,

      sequence_valid:
        false

    };

  }


  /*
   * S3:
   *
   * Unauthorized camera ID.
   */

  if (
    !AUTHORIZED_CAMERAS.has(
      cameraId
    )
  ) {

    return {

      ok: false,

      reason:
        "unauthorized_camera",

      camera_authorized:
        false,

      sequence_valid:
        true

    };

  }


  const sequence =
    Number(
      tx.sequence
    );


  /*
   * Security experiments require a real
   * numeric freshness counter.
   */

  if (
    REQUIRE_NUMERIC_SEQUENCE &&
    !Number.isInteger(
      sequence
    )
  ) {

    return {

      ok: false,

      reason:
        "invalid_sequence",

      camera_authorized:
        true,

      sequence_valid:
        false

    };

  }


  const last =
    highestSequenceByCamera.get(
      cameraId
    );


  /*
   * S1:
   *
   * Old or replayed sequence.
   */

  if (
    last !== undefined &&
    sequence <= last
  ) {

    return {

      ok: false,

      reason:
        "stale_or_replayed_sequence",

      camera_authorized:
        true,

      sequence_valid:
        false,

      previous_sequence:
        last

    };

  }


  return {

    ok: true,

    camera_authorized:
      true,

    sequence_valid:
      true,

    sequence

  };

}


/* ============================================================
   ACCEPT TRANSACTION
   ============================================================ */

function acceptTransaction(
  tx
) {

  if (
    !tx ||
    !tx.id
  ) {

    return {

      accepted: false,

      reason:
        "missing_transaction_id",

      duplicate_tx:
        false

    };

  }


  /*
   * S1 exact replay.
   */

  if (
    seenTx.has(
      tx.id
    )
  ) {

    return {

      accepted: false,

      reason:
        "duplicate_tx_id",

      duplicate_tx:
        true

    };

  }


  const security =
    validateSecurityTransaction(
      tx
    );


  if (
    !security.ok
  ) {

    if (
      SECURITY_MODE
    ) {

      appendSecurityMetric({

        test_id:
          tx.security_test_id ||
          SECURITY_TEST ||
          "S1-S5",

        run_id:
          tx.security_run_id ||
          "",

        attack_type:
          tx.attack_type ||
          SECURITY_TEST,

        transaction_id:
          tx.id,

        camera_id:
          tx.camera_id,

        sequence:
          tx.sequence,

        expected_result:
          "rejected",

        actual_result:
          "rejected",

        accepted:
          false,

        detected:
          true,

        rejection_reason:
          security.reason,

        signature_valid:
          tx.security_signature_valid ??
          "",

        camera_authorized:
          security.camera_authorized,

        sequence_valid:
          security.sequence_valid,

        duplicate_tx:
          false,

        offchain_hash_match:
          tx.offchain_hash_match ??
          "",

        detection_latency_ms:
          tx.security_detection_latency_ms ??
          "",

        layer:
          "P2P_VALIDATOR"

      });

    }


    return {

      accepted: false,

      reason:
        security.reason,

      security

    };

  }


  /*
   * Mark transaction as seen only after
   * security validation succeeds.
   */

  seenTx.add(
    tx.id
  );


  if (
    !tx.consensus_start_timestamp
  ) {

    tx.consensus_start_timestamp =
      Date.now();

  }


  txPool.set(
    tx.id,
    tx
  );


  /*
   * Reserve the sequence immediately.
   *
   * This is important because two identical sequence
   * numbers could otherwise enter the transaction pool
   * before PBFT commits the first one.
   */

  if (
    SECURITY_MODE &&
    security.sequence !== undefined
  ) {

    highestSequenceByCamera.set(
      String(
        tx.camera_id
      ),
      security.sequence
    );

    saveSecuritySequenceState();

  }


  return {

    accepted: true,

    reason:
      "accepted",

    security

  };

}


/* ============================================================
   SWARM
   ============================================================ */

const swarm =
  Swarm(
    defaults({
      id:
        myPeerId
    })
  );


(async () => {

  const port =
    await getPort();

  swarm.listen(
    port
  );

  swarm.join(
    NETWORK_NAME
  );

  console.log(
    `Validator ${VALIDATOR_ID} (${NODE_ID}) listening on ${port}`
  );

  console.log(
    `PBFT N=${N}, F=${F}, quorum=${QUORUM}`
  );

  swarm.on(
    "connection",
    (conn, info) => {

      const peerId =
        info.id.toString(
          "hex"
        );

      if (
        peers.has(
          peerId
        )
      ) {

        conn.destroy();

        return;

      }

      peers.set(
        peerId,
        {

          conn,

          state:
            STATE.INIT,

          aesKey:
            null,

          recvBuffer:
            "",

          inbox:
            []

        }
      );


      conn.on(
        "data",
        data =>
          handleRaw(
            peerId,
            data
          )
      );


      conn.on(
        "close",
        () => {

          peers.delete(
            peerId
          );

        }
      );


      conn.on(
        "error",
        error => {

          console.error(
            "Peer connection error:",
            error.message
          );

        }
      );


      if (
        peerId >
        myPeerIdHex
      ) {

        startHandshake(
          peerId
        );

      }

    }
  );

})();


/* ============================================================
   HANDSHAKE
   ============================================================ */

function startHandshake(
  peerId
) {

  const peer =
    peers.get(
      peerId
    );

  if (
    !peer ||
    peer.state !==
      STATE.INIT
  ) {

    return;

  }

  send(
    peerId,
    {

      type:
        "HELLO",

      pk:
        publicKey.toString(
          "base64"
        )

    }
  );

  peer.state =
    STATE.HELLO_SENT;

}


/* ============================================================
   RECEIVE
   ============================================================ */

function handleRaw(
  peerId,
  raw
) {

  const peer =
    peers.get(
      peerId
    );

  if (!peer) {

    return;

  }

  peer.recvBuffer +=
    raw.toString();

  let index;

  while (
    (
      index =
        peer.recvBuffer.indexOf(
          "\n"
        )
    ) >= 0
  ) {

    const line =
      peer.recvBuffer.slice(
        0,
        index
      );

    peer.recvBuffer =
      peer.recvBuffer.slice(
        index + 1
      );

    if (
      !line.trim()
    ) {

      continue;

    }

    try {

      const message =
        JSON.parse(
          line
        );

      handleMessage(
        peerId,
        message
      );

    } catch (error) {

      console.error(
        "Invalid peer JSON:",
        error.message
      );

    }

  }

}


/* ============================================================
   MESSAGE
   ============================================================ */

function handleMessage(
  peerId,
  msg
) {

  const peer =
    peers.get(
      peerId
    );

  if (!peer) {

    return;

  }


  /* HELLO */

  if (
    msg.type === "HELLO" &&
    peer.state === STATE.INIT
  ) {

    try {

      const peerPK =
        Buffer.from(
          msg.pk,
          "base64"
        );

      const ctPtr =
        ref.alloc(
          uint8Ptr
        );

      const ctLen =
        ref.alloc(
          "size_t"
        );

      const ssPtr =
        ref.alloc(
          uint8Ptr
        );

      const ssLen =
        ref.alloc(
          "size_t"
        );

      const ret =
        pqc.pqc_kem_encaps(

          KEM_ALGO,
          peerPK,
          ctPtr,
          ctLen,
          ssPtr,
          ssLen

        );

      if (
        ret !== 0
      ) {

        throw new Error(
          `KEM encapsulation failed: ${ret}`
        );

      }

      const ct =
        ref.reinterpret(
          ctPtr.deref(),
          ctLen.deref()
        );

      const ss =
        ref.reinterpret(
          ssPtr.deref(),
          ssLen.deref()
        );

      peer.aesKey =
        crypto
          .createHash("sha256")
          .update(ss)
          .digest();

      peer.state =
        STATE.SECURE;

      send(
        peerId,
        {

          type:
            "CIPHERTEXT",

          ct:
            ct.toString(
              "base64"
            )

        }
      );

    } catch (error) {

      console.error(
        "HELLO processing error:",
        error.message
      );

    }

    return;

  }


  /* CIPHERTEXT */

  if (
    msg.type ===
      "CIPHERTEXT" &&
    peer.state ===
      STATE.HELLO_SENT
  ) {

    try {

      const ct =
        Buffer.from(
          msg.ct,
          "base64"
        );

      const ssPtr =
        ref.alloc(
          uint8Ptr
        );

      const ssLen =
        ref.alloc(
          "size_t"
        );

      const ret =
        pqc.pqc_kem_decaps(

          KEM_ALGO,
          ct,
          secretKey,
          ssPtr,
          ssLen

        );

      if (
        ret !== 0
      ) {

        throw new Error(
          `KEM decapsulation failed: ${ret}`
        );

      }

      const ss =
        ref.reinterpret(
          ssPtr.deref(),
          ssLen.deref()
        );

      peer.aesKey =
        crypto
          .createHash("sha256")
          .update(ss)
          .digest();

      peer.state =
        STATE.SECURE;

      console.log(
        "Secure channel:",
        peerId.substring(
          0,
          12
        )
      );

    } catch (error) {

      console.error(
        "CIPHERTEXT processing error:",
        error.message
      );

    }

    return;

  }


  /* DATA */

  if (
    msg.type === "DATA" &&
    peer.state === STATE.SECURE
  ) {

    try {

      const decrypted =
        aesDecrypt(
          peer.aesKey,
          msg.payload
        );

      const plain =
        JSON.parse(
          decrypted.toString(
            "utf8"
          )
        );

      peer.inbox.push(
        plain
      );

      processInbox(
        peerId
      );

    } catch (error) {

      /*
       * S4:
       *
       * AES-GCM authentication fails if the encrypted
       * P2P packet has been modified.
       */

      console.error(
        "AES-GCM authentication/decryption failure:",
        error.message
      );

      if (
        SECURITY_MODE
      ) {

        appendSecurityMetric({

          test_id:
            "S4",

          run_id:
            "",

          attack_type:
            "P2P_AES_GCM_TAMPERING",

          transaction_id:
            "",

          camera_id:
            "",

          sequence:
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
            "aes_gcm_authentication_failed",

          signature_valid:
            "",

          camera_authorized:
            "",

          sequence_valid:
            "",

          duplicate_tx:
            "",

          offchain_hash_match:
            "",

          detection_latency_ms:
            "",

          layer:
            "P2P_VALIDATOR"

        });

      }

    }

  }

}


/* ============================================================
   INBOX
   ============================================================ */

function processInbox(
  peerId
) {

  const peer =
    peers.get(
      peerId
    );

  if (!peer) {

    return;

  }

  while (
    peer.inbox.length
  ) {

    handleSecure(
      peerId,
      peer.inbox.shift()
    );

  }

}


function handleSecure(
  peerId,
  msg
) {

  if (
    msg.type === "TX"
  ) {

    handleTx(
      peerId,
      msg.tx
    );

    return;

  }

  if (
    typeof msg.type ===
      "string" &&
    msg.type.startsWith(
      "PBFT_"
    )
  ) {

    handlePBFT(
      peerId,
      msg
    );

  }

}


/* ============================================================
   TRANSACTION
   ============================================================ */

function handleTx(
  peerId,
  tx
) {

  if (
    !tx ||
    !tx.id
  ) {

    return {

      accepted: false,

      reason:
        "missing_transaction_id"

    };

  }


  const result =
    acceptTransaction(
      tx
    );


  if (
    !result.accepted
  ) {

    console.log(
      `TX rejected | validator=${VALIDATOR_ID} | tx=${tx.id} | reason=${result.reason}`
    );

    return result;

  }


  if (
    !tx.consensus_start_timestamp
  ) {

    tx.consensus_start_timestamp =
      Date.now();

  }


  console.log(
    `TX received | validator=${VALIDATOR_ID} | camera=${tx.camera_id} | tx=${tx.id} | primary=${tx.primary_id || "unknown"}`
  );


  broadcast(
    peerId,
    {

      type:
        "TX",

      tx

    }
  );


  return result;

}


/* ============================================================
   PBFT
   ============================================================ */

function startPBFT(
  tx
) {

  const digest =
    hash(
      tx
    );

  txByDigest.set(
    digest,
    tx
  );

  if (
    pbftMetrics.has(
      digest
    )
  ) {

    return;

  }

  const wallClockNow =
    Date.now();

  const monotonicNow =
    nowNs();

  if (
    !tx.primary_id
  ) {

    tx.primary_id =
      myPeerIdHex;

  }

  pbftMetrics.set(
    digest,
    {

      tx_id:
        tx.id,

      primary_id:
        tx.primary_id,

      tx_submission_timestamp:
        tx.tx_submission_timestamp ||
        tx.consensus_start_timestamp ||
        wallClockNow,

      pbft_start_timestamp:
        wallClockNow,

      preprepare_timestamp:
        wallClockNow,

      prepare_quorum_timestamp:
        null,

      commit_start_timestamp:
        null,

      commit_quorum_timestamp:
        null,

      committed_timestamp:
        null,

      block_append_timestamp:
        null,

      start_ns:
        monotonicNow,

      preprepare_ns:
        monotonicNow,

      prepare_quorum_ns:
        null,

      commit_start_ns:
        null,

      commit_quorum_ns:
        null,

      block_append_ns:
        null

    }
  );

  pbft.preprepares.add(
    digest
  );

  pbft.prepares.set(
    digest,
    new Set([
      myPeerIdHex
    ])
  );


  broadcast(
    null,
    {

      type:
        "PBFT_PREPREPARE",

      digest,

      tx,

      primary_id:
        tx.primary_id

    }
  );


  broadcast(
    null,
    {

      type:
        "PBFT_PREPARE",

      digest,

      primary_id:
        tx.primary_id

    }
  );

}


/* ============================================================
   PBFT MESSAGE HANDLING
   ============================================================ */

function handlePBFT(
  peerId,
  msg
) {

  const digest =
    msg.digest;

  if (!digest) {

    return;

  }


  /* PRE-PREPARE */

  if (
    msg.type ===
      "PBFT_PREPREPARE"
  ) {

    if (
      msg.tx &&
      !txByDigest.has(
        digest
      )
    ) {

      txByDigest.set(
        digest,
        msg.tx
      );

    }

    if (
      pbft.preprepares.has(
        digest
      )
    ) {

      return;

    }

    pbft.preprepares.add(
      digest
    );

    const wallClockNow =
      Date.now();

    const monotonicNow =
      nowNs();

    const tx =
      txByDigest.get(
        digest
      );

    if (!tx) {

      return;

    }

    if (
      !pbftMetrics.has(
        digest
      )
    ) {

      pbftMetrics.set(
        digest,
        {

          tx_id:
            tx.id ||
            null,

          primary_id:
            tx.primary_id ||
            msg.primary_id ||
            null,

          tx_submission_timestamp:
            tx.tx_submission_timestamp ||
            tx.consensus_start_timestamp ||
            wallClockNow,

          pbft_start_timestamp:
            wallClockNow,

          preprepare_timestamp:
            wallClockNow,

          prepare_quorum_timestamp:
            null,

          commit_start_timestamp:
            null,

          commit_quorum_timestamp:
            null,

          committed_timestamp:
            null,

          block_append_timestamp:
            null,

          start_ns:
            monotonicNow,

          preprepare_ns:
            monotonicNow,

          prepare_quorum_ns:
            null,

          commit_start_ns:
            null,

          commit_quorum_ns:
            null,

          block_append_ns:
            null

        }
      );

    }

    const metrics =
      pbftMetrics.get(
        digest
      );

    metrics.preprepare_timestamp =
      wallClockNow;

    metrics.preprepare_ns =
      monotonicNow;

    if (
      !pbft.prepares.has(
        digest
      )
    ) {

      pbft.prepares.set(
        digest,
        new Set()
      );

    }

    pbft.prepares
      .get(digest)
      .add(
        myPeerIdHex
      );

    broadcast(
      null,
      {

        type:
          "PBFT_PREPARE",

        digest,

        primary_id:
          tx.primary_id ||
          msg.primary_id ||
          null

      }
    );

    return;

  }


  /* PREPARE */

  if (
    msg.type ===
      "PBFT_PREPARE"
  ) {

    if (
      !pbft.prepares.has(
        digest
      )
    ) {

      pbft.prepares.set(
        digest,
        new Set()
      );

    }

    pbft.prepares
      .get(digest)
      .add(
        peerId
      );

    const prepareSet =
      pbft.prepares.get(
        digest
      );

    if (
      prepareSet.size >=
      QUORUM
    ) {

      const metrics =
        pbftMetrics.get(
          digest
        );

      if (
        metrics &&
        !metrics.prepare_quorum_timestamp
      ) {

        metrics.prepare_quorum_timestamp =
          Date.now();

        metrics.prepare_quorum_ns =
          nowNs();

      }

      if (
        !pbft.commits.has(
          digest
        )
      ) {

        pbft.commits.set(
          digest,
          new Set([
            myPeerIdHex
          ])
        );

        if (
          metrics
        ) {

          metrics.commit_start_timestamp =
            Date.now();

          metrics.commit_start_ns =
            nowNs();

        }

        broadcast(
          null,
          {

            type:
              "PBFT_COMMIT",

            digest,

            primary_id:
              metrics?.primary_id ||
              null

          }
        );

      }

    }

    return;

  }


  /* COMMIT */

  if (
    msg.type ===
      "PBFT_COMMIT"
  ) {

    if (
      !pbft.commits.has(
        digest
      )
    ) {

      pbft.commits.set(
        digest,
        new Set()
      );

    }

    pbft.commits
      .get(digest)
      .add(
        peerId
      );

    const commitSet =
      pbft.commits.get(
        digest
      );

    if (
      commitSet.size >=
      QUORUM
    ) {

      const metrics =
        pbftMetrics.get(
          digest
        );

      if (
        metrics &&
        !metrics.commit_quorum_timestamp
      ) {

        metrics.commit_quorum_timestamp =
          Date.now();

        metrics.commit_quorum_ns =
          nowNs();

      }

      if (
        !pbft.committed.has(
          digest
        )
      ) {

        pbft.committed.add(
          digest
        );

        if (
          metrics
        ) {

          metrics.committed_timestamp =
            Date.now();

        }

        addBlock(
          digest
        );

      }

    }

  }

}


/* ============================================================
   BLOCK CREATION
   ============================================================ */

function addBlock(
  digest
) {

  if (
    blockchain.some(
      block =>
        block.digest ===
        digest
    )
  ) {

    return;

  }

  const tx =
    txByDigest.get(
      digest
    );

  if (!tx) {

    return;

  }

  const metrics =
    pbftMetrics.get(
      digest
    );

  const blockAppendStartNs =
    nowNs();

  const blockAppendTimestamp =
    Date.now();

  if (
    metrics
  ) {

    metrics.block_append_timestamp =
      blockAppendTimestamp;

    metrics.block_append_ns =
      blockAppendStartNs;

  }

  const consensusStartNs =
    metrics?.start_ns ||
    blockAppendStartNs;

  const preprepareNs =
    metrics?.preprepare_ns ||
    consensusStartNs;

  const prepareQuorumNs =
    metrics?.prepare_quorum_ns ||
    blockAppendStartNs;

  const commitStartNs =
    metrics?.commit_start_ns ||
    prepareQuorumNs;

  const commitQuorumNs =
    metrics?.commit_quorum_ns ||
    blockAppendStartNs;

  const endTime =
    blockAppendTimestamp;

  const consensusStart =
    metrics?.pbft_start_timestamp ||
    tx.consensus_start_timestamp ||
    endTime;

  const preprepareTimestamp =
    metrics?.preprepare_timestamp ||
    consensusStart;

  const prepareQuorumTimestamp =
    metrics?.prepare_quorum_timestamp ||
    endTime;

  const commitQuorumTimestamp =
    metrics?.commit_quorum_timestamp ||
    endTime;

  const committedTimestamp =
    metrics?.committed_timestamp ||
    endTime;


  /* SIGNED PAYLOAD */

  let signedData = {};

  if (
    tx.signed_payload ||
    tx.payload
  ) {

    try {

      signedData =
        JSON.parse(
          Buffer.from(
            tx.signed_payload ||
            tx.payload,
            "base64"
          ).toString(
            "utf8"
          )
        );

    } catch (
      error
    ) {

      signedData = {};

    }

  }


  /* NORMALIZED DATA */

  const cameraId =
    tx.camera_id ??
    signedData.camera_id ??
    null;

  const dataset =
    tx.dataset ??
    signedData.dataset ??
    null;

  const sequence =
    tx.sequence ??
    signedData.sequence ??
    null;

  const frameId =
    tx.frame_id ??
    signedData.frame_id ??
    null;

  const image =
    tx.image ??
    signedData.image ??
    signedData.frame_file ??
    null;

  const imageIndex =
    tx.image_index ??
    signedData.image_index ??
    null;

  const frameFile =
    tx.frame_file ??
    signedData.frame_file ??
    tx.image ??
    signedData.image ??
    null;

  const detectionTimestamp =
    tx.detection_timestamp ??
    signedData.timestamp ??
    null;

  const detections =
    tx.detections ??
    signedData.detections ??
    [];

  const detectionCount =
    tx.detection_count ??
    signedData.detection_count ??
    detections.length;


  /* HASH CHAIN */

  const previousHash =
    blockchain.length > 0
      ? blockchain[
          blockchain.length - 1
        ].digest
      : "GENESIS";


  /* DURATIONS */

  const pbftPreprepareMs =
    elapsedMs(
      consensusStartNs,
      preprepareNs
    );

  const pbftPrepareMs =
    elapsedMs(
      preprepareNs,
      prepareQuorumNs
    );

  const pbftCommitPhaseMs =
    elapsedMs(
      commitStartNs,
      commitQuorumNs
    );

  const pbftLatencyMs =
    elapsedMs(
      consensusStartNs,
      commitQuorumNs
    );

  const transactionCommitLatencyMs =
    pbftLatencyMs;


  /* BLOCK */

  const block = {

    index:
      blockchain.length,

    digest,

    previousHash,

    clock:
      endTime,

    txId:
      tx.id,

    validator_id:
      VALIDATOR_ID,

    node_id:
      NODE_ID,

    primary_id:
      tx.primary_id ||
      metrics?.primary_id ||
      null,

    camera_id:
      cameraId,

    dataset,

    sequence,

    image,

    image_index:
      imageIndex,

    frame_id:
      frameId,

    frame_file:
      frameFile,

    detection_timestamp:
      detectionTimestamp,

    detection_count:
      detectionCount,

    detections,

    pqc:
      tx.pqc || {

        algorithm:
          tx.algorithm ||
          null,

        algorithm_code:
          tx.algorithm_code ||
          null,

        signature:
          tx.signature ||
          null,

        publicKey:
          tx.publicKey ||
          null

      },

    signed_payload:
      tx.signed_payload ||
      tx.payload ||
      null,

    /*
     * S5:
     *
     * Store the off-chain SHA-256 evidence
     * in the immutable blockchain record.
     */

    offchain:
      tx.offchain || {

        media_sha256:
          null,

        media_path:
          null,

        media_file:
          null

      },

    pbft: {

      start_timestamp:
        consensusStart,

      preprepare_timestamp:
        preprepareTimestamp,

      prepare_quorum_timestamp:
        prepareQuorumTimestamp,

      commit_quorum_timestamp:
        commitQuorumTimestamp,

      pbft_preprepare_ms:
        roundMs(
          pbftPreprepareMs
        ),

      pbft_prepare_ms:
        roundMs(
          pbftPrepareMs
        ),

      pbft_commit_phase_ms:
        roundMs(
          pbftCommitPhaseMs
        ),

      pbft_latency_ms:
        roundMs(
          pbftLatencyMs
        )

    },

    transaction_commit_latency_ms:
      roundMs(
        transactionCommitLatencyMs
      ),

    blockchain_commit_latency_ms:
      roundMs(
        pbftLatencyMs
      ),

    source_timing:
      tx.source_timing ||
      null,

    node_timing: {

      pqc_verification_ms:
        tx.pqc?.verification_ms ??
        null

    },

    tx_submission_timestamp:
      tx.tx_submission_timestamp ||
      tx.consensus_start_timestamp ||
      null,

    blockchain_commit_timestamp:
      committedTimestamp,

    total_time:
      endTime

  };


  blockchain.push(
    block
  );


  const writeMs =
    saveBlockchain();

  const blockAppendEndNs =
    nowNs();

  const totalConsensusToDiskMs =
    elapsedMs(
      consensusStartNs,
      blockAppendEndNs
    );


  block.blockchain_write_ms =
    writeMs !== null
      ? roundMs(writeMs)
      : null;

  block.total_consensus_to_disk_ms =
    roundMs(
      totalConsensusToDiskMs
    );


  /* CANONICAL METRICS */

  const isPrimary =
    (
      tx.primary_id &&
      tx.primary_id ===
        myPeerIdHex
    );


  if (
    isPrimary &&
    !canonicalMetricsWritten.has(
      tx.id
    )
  ) {

    canonicalMetricsWritten.add(
      tx.id
    );

    commitHistory.push(
      committedTimestamp
    );

    commitHistory.sort(
      (a, b) =>
        a - b
    );

    let processTPS =
      0;

    if (
      commitHistory.length > 1
    ) {

      const first =
        commitHistory[0];

      const last =
        commitHistory[
          commitHistory.length - 1
        ];

      const durationSeconds =
        (
          last -
          first
        ) / 1000;

      if (
        durationSeconds > 0
      ) {

        processTPS =
          (
            commitHistory.length - 1
          ) /
          durationSeconds;

      }

    }

    const WINDOW_MS =
      10000;

    const cutoff =
      committedTimestamp -
      WINDOW_MS;

    const recentCommits =
      commitHistory.filter(
        timestamp =>
          timestamp >=
          cutoff
      );

    const rollingTPS =
      recentCommits.length /
      (
        WINDOW_MS / 1000
      );

    const committedTPS =
      processTPS > 0
        ? processTPS
        : rollingTPS;


    appendPBFTMetrics([

      VALIDATOR_ID,

      NODE_ID,

      new Date(
        committedTimestamp
      ).toISOString(),

      block.index,

      tx.id,

      digest,

      tx.primary_id ||
        metrics?.primary_id ||
        "",

      cameraId,

      dataset,

      sequence,

      frameId,

      imageIndex,

      detectionCount,

      tx.tx_submission_timestamp ||
        tx.consensus_start_timestamp ||
        "",

      consensusStart,

      preprepareTimestamp,

      prepareQuorumTimestamp,

      metrics?.commit_start_timestamp ||
        "",

      commitQuorumTimestamp,

      blockAppendTimestamp,

      roundMs(
        pbftPreprepareMs
      ),

      roundMs(
        pbftPrepareMs
      ),

      roundMs(
        pbftCommitPhaseMs
      ),

      roundMs(
        pbftLatencyMs
      ),

      roundMs(
        transactionCommitLatencyMs
      ),

      writeMs !== null
        ? roundMs(writeMs)
        : "",

      roundMs(
        totalConsensusToDiskMs
      ),

      roundMs(
        committedTPS
      )

    ]);

  }


  txPool.delete(
    tx.id
  );

}


/* ============================================================
   NETWORK SEND
   ============================================================ */

function send(
  peerId,
  obj
) {

  const peer =
    peers.get(
      peerId
    );

  if (
    !peer ||
    !peer.conn ||
    peer.conn.destroyed
  ) {

    return;

  }

  peer.conn.write(
    JSON.stringify(
      obj
    ) +
    "\n"
  );

}


function sendEncrypted(
  peerId,
  obj
) {

  const peer =
    peers.get(
      peerId
    );

  if (
    !peer ||
    peer.state !==
      STATE.SECURE ||
    !peer.aesKey
  ) {

    return;

  }

  try {

    const payload =
      aesEncrypt(
        peer.aesKey,
        Buffer.from(
          JSON.stringify(
            obj
          )
        )
      );


    /*
     * S4 P2P attack.
     *
     * Modify one byte after encryption.
     * AES-GCM must reject it at the receiver.
     */

    if (
      SECURITY_MODE &&
      tamperP2POnce
    ) {

      const encrypted =
        Buffer.from(
          payload.data,
          "base64"
        );

      if (
        encrypted.length > 0
      ) {

        encrypted[0] ^=
          0x01;

        payload.data =
          encrypted.toString(
            "base64"
          );

      }

      tamperP2POnce =
        false;

      console.log(
        "⚠️ SECURITY S4: one P2P AES-GCM packet was intentionally modified"
      );

    }


    send(
      peerId,
      {

        type:
          "DATA",

        payload

      }
    );

  } catch (error) {

    console.error(
      "sendEncrypted error:",
      error.message
    );

  }

}


function broadcast(
  except,
  obj
) {

  for (
    const [
      id,
      peer
    ]
    of peers
  ) {

    if (
      peer.state ===
        STATE.SECURE &&
      id !== except
    ) {

      sendEncrypted(
        id,
        obj
      );

    }

  }

}


/* ============================================================
   HASH
   ============================================================ */

function hash(
  obj
) {

  return crypto
    .createHash(
      "sha256"
    )
    .update(
      JSON.stringify(
        obj
      )
    )
    .digest(
      "hex"
    );

}


/* ============================================================
   APPLICATION API
   ============================================================ */

function submitTx(
  tx
) {

  if (
    !tx ||
    !tx.id
  ) {

    return {

      accepted: false,

      reason:
        "missing_transaction_id"

    };

  }


  /*
   * Validate before assigning primary or entering PBFT.
   */

  const result =
    acceptTransaction(
      tx
    );


  if (
    !result.accepted
  ) {

    console.log(
      `Application TX rejected | tx=${tx.id} | reason=${result.reason}`
    );

    return result;

  }


  /*
   * Originating validator.
   */

  tx.primary_id =
    myPeerIdHex;


  tx.consensus_start_timestamp =
    Date.now();

  tx.tx_submission_timestamp =
    tx.consensus_start_timestamp;


  /*
   * The TX has already been placed in txPool by
   * acceptTransaction().
   */

  console.log(
    "\nTX FROM APPLICATION"
  );

  console.log(
    "Validator:",
    VALIDATOR_ID
  );

  console.log(
    "TX ID:",
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


  broadcast(
    null,
    {

      type:
        "TX",

      tx

    }
  );


  startPBFT(
    tx
  );


  return {

    accepted: true,

    reason:
      "accepted",

    tx_id:
      tx.id

  };

}


/* ============================================================
   METRICS API
   ============================================================ */

function getPBFTMetrics(
  txId
) {

  for (
    const metrics
    of pbftMetrics.values()
  ) {

    if (
      metrics.tx_id ===
      txId
    ) {

      return metrics;

    }

  }

  return null;

}


/* ============================================================
   SECURITY API
   ============================================================ */

function getSecurityState() {

  return {

    security_mode:
      SECURITY_MODE,

    security_test:
      SECURITY_TEST,

    authorized_cameras:
      Array.from(
        AUTHORIZED_CAMERAS
      ),

    highest_sequence_by_camera:
      Object.fromEntries(
        highestSequenceByCamera
      ),

    security_metrics_file:
      SECURITY_METRICS_FILE

  };

}


/* ============================================================
   EXPORTS
   ============================================================ */

module.exports = {

  submitTx,

  getPBFTMetrics,

  getSecurityState,

  appendSecurityMetric

};
