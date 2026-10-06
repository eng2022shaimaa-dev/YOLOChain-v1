/*****************************************************************
 * YOLOChain
 * Experiment D — OPTIMIZED PERSISTENCE + FULL CRYPTO INSTRUMENTATION
 *
 * YOLOv8 + MQTT + PQC KEM + AES-256-GCM + PBFT + Blockchain
 *
 * Instrumented measurements:
 *
 *   1. Kyber KEM key generation
 *   2. Kyber KEM encapsulation
 *   3. Kyber KEM decapsulation
 *   4. SHA-256 key derivation
 *   5. AES-256-GCM encryption
 *   6. AES-256-GCM decryption
 *   7. PBFT PRE-PREPARE
 *   8. PBFT PREPARE
 *   9. PBFT COMMIT
 *  10. PBFT total latency
 *  11. Blockchain append/write
 *  12. Consensus-to-disk
 *  13. Source-to-canonical-commit E2E
 *
 * IMPORTANT:
 *
 * E2E is NOT calculated by summing components.
 *
 *     E2E =
 *       canonical_commit_timestamp
 *       -
 *       source_timestamp
 *
 * when a valid source timestamp is available.
 *
 * Component measurements are independent diagnostic measurements.
 *****************************************************************/

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
  String(process.env.VALIDATOR_ID || "1");

const NODE_ID =
  String(
    process.env.NODE_ID ||
    `validator_${VALIDATOR_ID}`
  );

const ROOT_RESULTS_DIR =
  path.join(__dirname, "results_D");

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

const CRYPTO_METRICS_FILE =
  path.join(
    RESULTS_DIR,
    "crypto_metrics.csv"
  );


console.log(
  "============================================================"
);

console.log(
  "YOLOChain Experiment D"
);

console.log(
  "OPTIMIZED PERSISTENCE + CRYPTO INSTRUMENTATION"
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
  "Crypto metrics:",
  CRYPTO_METRICS_FILE
);

console.log(
  "Persistence: APPEND-ONLY BLOCK INSERTION"
);

console.log(
  "============================================================"
);


/* ============================================================
   NETWORK
   ============================================================ */

const NETWORK_NAME =
  "myBlockchain";


/* ============================================================
   PQC KEM
   ============================================================ */

/*
 * According to the current liboqs wrapper configuration:
 *
 *   KEM_ALGO = "1"
 *
 * must correspond to the Kyber/Kyber-family configuration used
 * by r1_pqc_kem_lib.so.
 *
 * The exact algorithm name should be confirmed against the
 * compiled native library if the wrapper has been changed.
 */

const KEM_ALGO =
  "1";


/*
 * Label used in the measurement CSV.
 *
 * This is intentionally a descriptive label. It does not alter
 * the native library call.
 */

const KEM_NAME =
  process.env.KEM_NAME || "Kyber";


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
   DIRECTORIES
   ============================================================ */

if (
  !fs.existsSync(DATA_DIR)
) {

  fs.mkdirSync(
    DATA_DIR,
    {
      recursive: true
    }
  );

}

if (
  !fs.existsSync(RESULTS_DIR)
) {

  fs.mkdirSync(
    RESULTS_DIR,
    {
      recursive: true
    }
  );

}


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
  "source_timestamp",

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

  "e2e_source_to_commit_ms",

  "committed_tps"

].join(",");


if (
  !fs.existsSync(PBFT_METRICS_FILE)
) {

  fs.writeFileSync(
    PBFT_METRICS_FILE,
    PBFT_CSV_HEADER + "\n"
  );

}


/* ============================================================
   CRYPTO CSV
   ============================================================ */

const CRYPTO_CSV_HEADER = [

  "validator_id",
  "node_id",
  "timestamp",
  "operation",
  "algorithm",
  "latency_ms"

].join(",");


if (
  !fs.existsSync(CRYPTO_METRICS_FILE)
) {

  fs.writeFileSync(
    CRYPTO_METRICS_FILE,
    CRYPTO_CSV_HEADER + "\n"
  );

}


/* ============================================================
   CSV HELPERS
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


function appendPBFTMetrics(row) {

  fs.appendFileSync(
    PBFT_METRICS_FILE,
    row
      .map(csvEscape)
      .join(",") +
    "\n"
  );

}


function appendCryptoMetric(
  operation,
  algorithm,
  latencyMs
) {

  if (
    latencyMs === null ||
    latencyMs === undefined
  ) {

    return;

  }

  fs.appendFileSync(

    CRYPTO_METRICS_FILE,

    [

      VALIDATOR_ID,

      NODE_ID,

      new Date().toISOString(),

      operation,

      algorithm,

      roundMs(latencyMs)

    ]
      .map(csvEscape)
      .join(",") +

    "\n"

  );

}


/* ============================================================
   TIMING
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


function roundMs(value) {

  if (
    value === null ||
    value === undefined ||
    Number.isNaN(value)
  ) {

    return "";

  }

  return Number(
    value.toFixed(3)
  );

}


/* ============================================================
   CRYPTO TIMING HELPER
   ============================================================ */

function measureCrypto(
  operation,
  algorithm,
  fn
) {

  const start =
    nowNs();

  const result =
    fn();

  const end =
    nowNs();

  const latency =
    elapsedMs(
      start,
      end
    );

  appendCryptoMetric(
    operation,
    algorithm,
    latency
  );

  return result;

}


/* ============================================================
   PQC LIBRARY
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

  return measureCrypto(
    "AES_ENCRYPT",
    "AES-256-GCM",
    () => {

      const iv =
        crypto.randomBytes(12);

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
  );

}


function aesDecrypt(
  key,
  payload
) {

  return measureCrypto(
    "AES_DECRYPT",
    "AES-256-GCM",
    () => {

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
  );

}


/* ============================================================
   SHA-256 KDF
   ============================================================ */

function deriveAESKey(
  sharedSecret
) {

  return measureCrypto(
    "SHA256_KDF",
    "SHA-256",
    () => {

      return crypto
        .createHash("sha256")
        .update(sharedSecret)
        .digest();

    }
  );

}


/* ============================================================
   PEER STATE
   ============================================================ */

const STATE = {

  INIT:
    "INIT",

  HELLO_SENT:
    "HELLO_SENT",

  SECURE:
    "SECURE"

};


/* ============================================================
   PEER ID
   ============================================================ */

const myPeerId =
  crypto.randomBytes(32);

const myPeerIdHex =
  myPeerId.toString("hex");


console.log(
  "My Peer ID:",
  myPeerIdHex
);


/* ============================================================
   KEM KEYPAIR
   ============================================================ */

const pkPtr =
  ref.alloc(uint8Ptr);

const pkLen =
  ref.alloc("size_t");

const skPtr =
  ref.alloc(uint8Ptr);

const skLen =
  ref.alloc("size_t");


console.log(
  "Generating PQC KEM keypair..."
);


/*
 * Key generation occurs once when the validator starts.
 *
 * Therefore it is an initialization measurement, not a
 * per-transaction latency.
 *
 * We record it once in crypto_metrics.csv.
 */

const keypairStart =
  nowNs();

const keypairResult =
  pqc.pqc_kem_keypair(
    KEM_ALGO,
    pkPtr,
    pkLen,
    skPtr,
    skLen
  );

const keypairEnd =
  nowNs();


const keypairLatency =
  elapsedMs(
    keypairStart,
    keypairEnd
  );


appendCryptoMetric(
  "KEYGEN",
  KEM_NAME,
  keypairLatency
);


console.log(
  "PQC KEM keypair time:",
  roundMs(keypairLatency),
  "ms"
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


console.log(
  "PQC KEM keypair generated"
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


/* ============================================================
   BLOCKCHAIN LOAD
   ============================================================ */

function loadBlockchain() {

  if (
    !fs.existsSync(CHAIN_FILE)
  ) {

    console.log(
      "Starting new blockchain:",
      CHAIN_FILE
    );

    fs.writeFileSync(
      CHAIN_FILE,
      "[\n]\n",
      "utf8"
    );

    return [];

  }


  try {

    const data =
      fs.readFileSync(
        CHAIN_FILE,
        "utf8"
      );

    if (
      !data.trim()
    ) {

      fs.writeFileSync(
        CHAIN_FILE,
        "[\n]\n",
        "utf8"
      );

      return [];

    }


    const chain =
      JSON.parse(data);


    if (
      !Array.isArray(chain)
    ) {

      throw new Error(
        "Blockchain root is not an array"
      );

    }


    console.log(
      "Blockchain loaded:",
      chain.length,
      "blocks"
    );


    return chain;

  } catch (error) {

    console.error(
      "Blockchain load error:",
      error.message
    );

    throw error;

  }

}


const blockchain =
  loadBlockchain();


/* ============================================================
   COMMITTED DIGEST INDEX
   ============================================================ */

const committedDigests =
  new Set(
    blockchain.map(
      block =>
        block.digest
    )
  );


/* ============================================================
   OPTIMIZED BLOCKCHAIN APPEND
   ============================================================ */

function appendBlockToJsonFile(
  block,
  isFirstBlock
) {

  const serializedBlock =
    JSON.stringify(
      block,
      null,
      2
    );


  const writeStart =
    nowNs();


  if (
    isFirstBlock
  ) {

    fs.writeFileSync(
      CHAIN_FILE,
      "[\n" +
      serializedBlock +
      "\n]\n",
      "utf8"
    );

  } else {

    const stat =
      fs.statSync(
        CHAIN_FILE
      );


    if (
      stat.size < 3
    ) {

      throw new Error(
        "Blockchain file is unexpectedly short"
      );

    }


    const fd =
      fs.openSync(
        CHAIN_FILE,
        "r+"
      );


    try {

      fs.ftruncateSync(
        fd,
        stat.size - 2
      );

    } finally {

      fs.closeSync(fd);

    }


    fs.appendFileSync(
      CHAIN_FILE,
      ",\n" +
      serializedBlock +
      "\n]\n",
      "utf8"
    );

  }


  const writeEnd =
    nowNs();


  return elapsedMs(
    writeStart,
    writeEnd
  );

}


/* ============================================================
   OPTIONAL VALIDATION
   ============================================================ */

function validateBlockchainFile() {

  const data =
    fs.readFileSync(
      CHAIN_FILE,
      "utf8"
    );

  const chain =
    JSON.parse(data);

  if (
    !Array.isArray(chain)
  ) {

    throw new Error(
      "Blockchain is not a JSON array"
    );

  }

  return chain.length;

}


/* ============================================================
   PBFT STATE
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


  swarm.listen(port);

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
        info.id.toString("hex");


      if (
        peers.has(peerId)
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

          peers.delete(peerId);

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

        startHandshake(peerId);

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
    peers.get(peerId);


  if (
    !peer ||
    peer.state !== STATE.INIT
  ) {

    return;

  }


  send(
    peerId,
    {

      type:
        "HELLO",

      pk:
        publicKey.toString("base64")

    }
  );


  peer.state =
    STATE.HELLO_SENT;

}


/* ============================================================
   STREAM RECEIVE
   ============================================================ */

function handleRaw(
  peerId,
  raw
) {

  const peer =
    peers.get(peerId);


  if (!peer) {

    return;

  }


  peer.recvBuffer +=
    raw.toString();


  let index;


  while (
    (
      index =
        peer.recvBuffer.indexOf("\n")
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
        JSON.parse(line);


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
   MESSAGE HANDLING
   ============================================================ */

function handleMessage(
  peerId,
  msg
) {

  const peer =
    peers.get(peerId);


  if (!peer) {

    return;

  }


  /* ---------------------------------------------------------
     HELLO
     --------------------------------------------------------- */

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
        ref.alloc(uint8Ptr);

      const ctLen =
        ref.alloc("size_t");

      const ssPtr =
        ref.alloc(uint8Ptr);

      const ssLen =
        ref.alloc("size_t");


      /*
       * Kyber encapsulation.
       */

      const encapsStart =
        nowNs();

      const ret =
        pqc.pqc_kem_encaps(

          KEM_ALGO,

          peerPK,

          ctPtr,

          ctLen,

          ssPtr,

          ssLen

        );

      const encapsEnd =
        nowNs();


      const encapsLatency =
        elapsedMs(
          encapsStart,
          encapsEnd
        );


      appendCryptoMetric(
        "ENCAPS",
        KEM_NAME,
        encapsLatency
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


      /*
       * SHA-256 shared-secret -> AES key.
       */

      peer.aesKey =
        deriveAESKey(ss);


      peer.state =
        STATE.SECURE;


      send(
        peerId,
        {

          type:
            "CIPHERTEXT",

          ct:
            ct.toString("base64")

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


  /* ---------------------------------------------------------
     CIPHERTEXT
     --------------------------------------------------------- */

  if (
    msg.type === "CIPHERTEXT" &&
    peer.state === STATE.HELLO_SENT
  ) {

    try {

      const ct =
        Buffer.from(
          msg.ct,
          "base64"
        );


      const ssPtr =
        ref.alloc(uint8Ptr);

      const ssLen =
        ref.alloc("size_t");


      /*
       * Kyber decapsulation.
       */

      const decapsStart =
        nowNs();

      const ret =
        pqc.pqc_kem_decaps(

          KEM_ALGO,

          ct,

          secretKey,

          ssPtr,

          ssLen

        );

      const decapsEnd =
        nowNs();


      const decapsLatency =
        elapsedMs(
          decapsStart,
          decapsEnd
        );


      appendCryptoMetric(
        "DECAPS",
        KEM_NAME,
        decapsLatency
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


      /*
       * SHA-256 shared-secret -> AES key.
       */

      peer.aesKey =
        deriveAESKey(ss);


      peer.state =
        STATE.SECURE;


      console.log(
        "Secure channel:",
        peerId.substring(0, 12)
      );


    } catch (error) {

      console.error(
        "CIPHERTEXT processing error:",
        error.message
      );

    }


    return;

  }


  /* ---------------------------------------------------------
     ENCRYPTED DATA
     --------------------------------------------------------- */

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
          decrypted.toString("utf8")
        );


      peer.inbox.push(
        plain
      );


      processInbox(peerId);


    } catch (error) {

      console.error(
        "AES decrypt error:",
        error.message
      );

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
    peers.get(peerId);


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
    typeof msg.type === "string" &&
    msg.type.startsWith("PBFT_")
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

    return;

  }


  if (
    seenTx.has(tx.id)
  ) {

    return;

  }


  seenTx.add(tx.id);


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


  console.log(
    `TX received | validator=${VALIDATOR_ID} | camera=${tx.camera_id} | tx=${tx.id}`
  );


  broadcast(
    peerId,
    {

      type:
        "TX",

      tx

    }
  );

}


/* ============================================================
   SOURCE TIMESTAMP EXTRACTION
   ============================================================ */

/*
 * The function intentionally accepts several common timestamp
 * representations because the camera-side implementation may
 * store source timing differently.
 *
 * IMPORTANT:
 * We prefer an actual source/camera timestamp.
 *
 * We DO NOT use tx_submission_timestamp as the source timestamp.
 *
 * If no source timestamp exists, E2E remains null rather than
 * silently changing the measurement definition.
 */

function getSourceTimestampMs(tx) {

  if (
    !tx
  ) {

    return null;

  }


  const st =
    tx.source_timing;


  if (
    st &&
    typeof st === "object"
  ) {

    const candidates = [

      st.source_timestamp_ms,

      st.sourceTimestampMs,

      st.camera_source_timestamp_ms,

      st.camera_timestamp_ms,

      st.timestamp_ms,

      st.source_timestamp,

      st.camera_source_timestamp,

      st.camera_timestamp,

      st.timestamp

    ];


    for (
      const value
      of candidates
    ) {

      const parsed =
        Number(value);


      if (
        Number.isFinite(parsed) &&
        parsed > 0
      ) {

        return normalizeTimestampMs(
          parsed
        );

      }

    }

  }


  /*
   * Some implementations may place source timestamp directly
   * in the transaction.
   */

  const directCandidates = [

    tx.source_timestamp_ms,

    tx.sourceTimestampMs,

    tx.camera_source_timestamp_ms,

    tx.camera_timestamp_ms,

    tx.source_timestamp,

    tx.camera_source_timestamp

  ];


  for (
    const value
    of directCandidates
  ) {

    const parsed =
      Number(value);


    if (
      Number.isFinite(parsed) &&
      parsed > 0
    ) {

      return normalizeTimestampMs(
        parsed
      );

    }

  }


  return null;

}


/*
 * Convert seconds / microseconds / nanoseconds where necessary
 * to JavaScript Date.now()-compatible milliseconds.
 *
 * Millisecond Unix timestamps are normally around 1e12.
 */

function normalizeTimestampMs(
  value
) {

  if (
    !Number.isFinite(value)
  ) {

    return null;

  }


  /*
   * nanoseconds
   */

  if (
    value > 1e17
  ) {

    return value / 1e6;

  }


  /*
   * microseconds
   */

  if (
    value > 1e14
  ) {

    return value / 1e3;

  }


  /*
   * seconds
   */

  if (
    value < 1e11
  ) {

    return value * 1000;

  }


  return value;

}


/* ============================================================
   PBFT START
   ============================================================ */

function startPBFT(
  tx
) {

  const digest =
    hash(tx);


  txByDigest.set(
    digest,
    tx
  );


  if (
    pbftMetrics.has(digest)
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


  const sourceTimestamp =
    getSourceTimestampMs(tx);


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

      source_timestamp:
        sourceTimestamp,

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


  console.log(
    "\nPBFT START"
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
    "Digest:",
    digest
  );


  console.log(
    "Source timestamp:",
    sourceTimestamp
  );


  console.log(
    "Primary:",
    tx.primary_id
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


  /* ---------------------------------------------------------
     PRE-PREPARE
     --------------------------------------------------------- */

  if (
    msg.type === "PBFT_PREPREPARE"
  ) {

    if (
      msg.tx &&
      !txByDigest.has(digest)
    ) {

      txByDigest.set(
        digest,
        msg.tx
      );

    }


    if (
      pbft.preprepares.has(digest)
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
      txByDigest.get(digest);


    if (!tx) {

      console.error(
        "PRE-PREPARE TX not found:",
        digest
      );

      return;

    }


    if (
      !pbftMetrics.has(digest)
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

          source_timestamp:
            getSourceTimestampMs(tx),

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
      pbftMetrics.get(digest);


    metrics.preprepare_timestamp =
      wallClockNow;

    metrics.preprepare_ns =
      monotonicNow;


    if (
      !pbft.prepares.has(digest)
    ) {

      pbft.prepares.set(
        digest,
        new Set()
      );

    }


    pbft.prepares
      .get(digest)
      .add(myPeerIdHex);


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


  /* ---------------------------------------------------------
     PREPARE
     --------------------------------------------------------- */

  if (
    msg.type === "PBFT_PREPARE"
  ) {

    if (
      !pbft.prepares.has(digest)
    ) {

      pbft.prepares.set(
        digest,
        new Set()
      );

    }


    pbft.prepares
      .get(digest)
      .add(peerId);


    const prepareSet =
      pbft.prepares.get(digest);


    if (
      prepareSet.size >= QUORUM
    ) {

      const metrics =
        pbftMetrics.get(digest);


      if (
        metrics &&
        !metrics.prepare_quorum_timestamp
      ) {

        metrics.prepare_quorum_timestamp =
          Date.now();

        metrics.prepare_quorum_ns =
          nowNs();


        console.log(
          "PBFT PREPARE QUORUM | tx=" +
          metrics.tx_id
        );

      }


      if (
        !pbft.commits.has(digest)
      ) {

        pbft.commits.set(
          digest,
          new Set([
            myPeerIdHex
          ])
        );


        if (metrics) {

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


        console.log(
          "PBFT COMMIT phase started"
        );

      }

    }


    return;

  }


  /* ---------------------------------------------------------
     COMMIT
     --------------------------------------------------------- */

  if (
    msg.type === "PBFT_COMMIT"
  ) {

    if (
      !pbft.commits.has(digest)
    ) {

      pbft.commits.set(
        digest,
        new Set()
      );

    }


    pbft.commits
      .get(digest)
      .add(peerId);


    const commitSet =
      pbft.commits.get(digest);


    if (
      commitSet.size >= QUORUM
    ) {

      const metrics =
        pbftMetrics.get(digest);


      if (
        metrics &&
        !metrics.commit_quorum_timestamp
      ) {

        metrics.commit_quorum_timestamp =
          Date.now();

        metrics.commit_quorum_ns =
          nowNs();


        console.log(
          "PBFT COMMIT QUORUM | tx=" +
          metrics.tx_id
        );

      }


      if (
        !pbft.committed.has(digest)
      ) {

        pbft.committed.add(digest);


        if (metrics) {

          metrics.committed_timestamp =
            Date.now();

        }


        addBlock(digest);

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

  /*
   * O(1) duplicate check.
   */

  if (
    committedDigests.has(digest)
  ) {

    return;

  }


  const tx =
    txByDigest.get(digest);


  if (!tx) {

    console.error(
      "TX not found:",
      digest
    );

    return;

  }


  const metrics =
    pbftMetrics.get(digest);


  const blockAppendStartNs =
    nowNs();

  const blockAppendTimestamp =
    Date.now();


  if (metrics) {

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


  /* ==========================================================
     SOURCE TIMESTAMP
     ========================================================== */

  const sourceTimestamp =
    metrics?.source_timestamp ??
    getSourceTimestampMs(tx);


  /*
   * IMPORTANT:
   *
   * E2E is source -> canonical commit.
   *
   * It is NOT:
   *
   *   YOLO + PQC + MQTT + PBFT
   *
   * It is measured directly from timestamps.
   */

  let e2eSourceToCommitMs =
    null;


  if (
    sourceTimestamp !== null &&
    Number.isFinite(sourceTimestamp)
  ) {

    e2eSourceToCommitMs =
      committedTimestamp -
      sourceTimestamp;


    /*
     * Guard against impossible negative clock differences.
     *
     * A negative result indicates inconsistent source/host clocks.
     * We therefore do not report it as a valid latency.
     */

    if (
      e2eSourceToCommitMs < 0
    ) {

      e2eSourceToCommitMs =
        null;

    }

  }


  /* ==========================================================
     SIGNED PAYLOAD
     ========================================================== */

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

          ).toString("utf8")

        );

    } catch (_) {

      signedData = {};

    }

  }


  /* ==========================================================
     NORMALIZED DATA
     ========================================================== */

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


  /* ==========================================================
     HASH CHAIN
     ========================================================== */

  const previousHash =
    blockchain.length > 0
      ? blockchain[
          blockchain.length - 1
        ].digest
      : "GENESIS";


  /* ==========================================================
     PBFT DURATIONS
     ========================================================== */

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


  /* ==========================================================
     BLOCK
     ========================================================== */

  const block = {

    index:
      blockchain.length,

    digest:
      digest,

    previousHash:
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

    dataset:
      dataset,

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
      detectionTimestamp,

    detection_count:
      detectionCount,

    detections:
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
        roundMs(pbftPreprepareMs),

      pbft_prepare_ms:
        roundMs(pbftPrepareMs),

      pbft_commit_phase_ms:
        roundMs(pbftCommitPhaseMs),

      pbft_latency_ms:
        roundMs(pbftLatencyMs)

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

    source_timestamp:
      sourceTimestamp,

    e2e_source_to_commit_ms:
      roundMs(
        e2eSourceToCommitMs
      ),

    blockchain_commit_timestamp:
      committedTimestamp,

    total_time:
      endTime

  };


  /* ==========================================================
     PERSIST BLOCK
     ========================================================== */

  const isFirstBlock =
    blockchain.length === 0;


  const writeMs =
    appendBlockToJsonFile(
      block,
      isFirstBlock
    );


  /*
   * Update in-memory chain only after successful disk append.
   */

  blockchain.push(block);

  committedDigests.add(digest);


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


  /* ==========================================================
     CANONICAL METRICS
     ========================================================== */

  const isPrimary =
    (
      tx.primary_id &&
      tx.primary_id ===
      myPeerIdHex
    );


  if (
    isPrimary &&
    !canonicalMetricsWritten.has(tx.id)
  ) {

    canonicalMetricsWritten.add(tx.id);


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
          timestamp >= cutoff
      );


    const rollingTPS =
      recentCommits.length /
      (WINDOW_MS / 1000);


    const committedTPS =
      processTPS > 0
        ? processTPS
        : rollingTPS;


    /* ========================================================
       CSV
       ======================================================== */

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

      sourceTimestamp !== null
        ? sourceTimestamp
        : "",

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
        e2eSourceToCommitMs
      ),

      roundMs(
        committedTPS
      )

    ]);


    /* ========================================================
       DISPLAY
       ======================================================== */

    console.log(
      "\nBLOCK COMMITTED"
    );


    console.log(
      "Validator:",
      VALIDATOR_ID
    );


    console.log(
      "Block index:",
      block.index
    );


    console.log(
      "TX ID:",
      tx.id
    );


    console.log(
      "Camera ID:",
      block.camera_id
    );


    console.log(
      "Dataset:",
      block.dataset
    );


    console.log(
      "Sequence:",
      block.sequence
    );


    console.log(
      "Detections:",
      block.detection_count
    );


    console.log(
      "----------------------------------------"
    );


    console.log(
      "PRE-PREPARE:",
      roundMs(pbftPreprepareMs),
      "ms"
    );


    console.log(
      "PREPARE:",
      roundMs(pbftPrepareMs),
      "ms"
    );


    console.log(
      "COMMIT:",
      roundMs(pbftCommitPhaseMs),
      "ms"
    );


    console.log(
      "PBFT total:",
      roundMs(pbftLatencyMs),
      "ms"
    );


    console.log(
      "TX -> PBFT commit:",
      roundMs(transactionCommitLatencyMs),
      "ms"
    );


    console.log(
      "Disk append:",
      writeMs !== null
        ? roundMs(writeMs)
        : "N/A",
      "ms"
    );


    console.log(
      "Consensus -> disk:",
      roundMs(totalConsensusToDiskMs),
      "ms"
    );


    console.log(
      "Source -> canonical commit E2E:",
      e2eSourceToCommitMs !== null
        ? roundMs(e2eSourceToCommitMs)
        : "N/A",
      "ms"
    );


    console.log(
      "Committed TPS:",
      roundMs(committedTPS)
    );


    console.log(
      "Rolling 10s TPS:",
      roundMs(rollingTPS)
    );


    console.log(
      "PBFT metrics:",
      PBFT_METRICS_FILE
    );

  }


  /* ==========================================================
     CLEANUP
     ========================================================== */

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
    peers.get(peerId);


  if (
    !peer ||
    !peer.conn ||
    peer.conn.destroyed
  ) {

    return;

  }


  peer.conn.write(
    JSON.stringify(obj) +
    "\n"
  );

}


/* ============================================================
   ENCRYPTED NETWORK SEND
   ============================================================ */

function sendEncrypted(
  peerId,
  obj
) {

  const peer =
    peers.get(peerId);


  if (
    !peer ||
    peer.state !== STATE.SECURE ||
    !peer.aesKey
  ) {

    return;

  }


  try {

    const payload =
      aesEncrypt(

        peer.aesKey,

        Buffer.from(
          JSON.stringify(obj)
        )

      );


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


/* ============================================================
   BROADCAST
   ============================================================ */

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
      peer.state === STATE.SECURE &&
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

    .createHash("sha256")

    .update(
      JSON.stringify(obj)
    )

    .digest("hex");

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

    console.error(
      "Invalid transaction"
    );

    return;

  }


  if (
    seenTx.has(tx.id)
  ) {

    return;

  }


  /*
   * This validator is the transaction originator.
   */

  tx.primary_id =
    myPeerIdHex;


  tx.consensus_start_timestamp =
    Date.now();


  tx.tx_submission_timestamp =
    tx.consensus_start_timestamp;


  seenTx.add(tx.id);


  txPool.set(
    tx.id,
    tx
  );


  console.log(
    "\nTX FROM APPLICATION"
  );


  console.log(
    "Validator:",
    VALIDATOR_ID
  );


  console.log(
    "Node ID:",
    NODE_ID
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
    "Dataset:",
    tx.dataset
  );


  console.log(
    "Sequence:",
    tx.sequence
  );


  console.log(
    "Frame:",
    tx.frame_id ??
    tx.image_index
  );


  console.log(
    "Detections:",
    tx.detection_count
  );


  console.log(
    "Primary:",
    tx.primary_id
  );


  /*
   * IMPORTANT:
   *
   * The original camera-side source_timing must already be
   * present in tx when submitTx() is called.
   *
   * We do not overwrite it here.
   */

  console.log(
    "Source timestamp:",
    getSourceTimestampMs(tx)
  );


  broadcast(
    null,
    {

      type:
        "TX",

      tx

    }
  );


  startPBFT(tx);

}


/* ============================================================
   OPTIONAL METRICS API
   ============================================================ */

function getPBFTMetrics(
  txId
) {

  for (
    const metrics
    of pbftMetrics.values()
  ) {

    if (
      metrics.tx_id === txId
    ) {

      return metrics;

    }

  }


  return null;

}


/* ============================================================
   OPTIONAL BLOCKCHAIN API
   ============================================================ */

function getBlockchainLength() {

  return blockchain.length;

}


/* ============================================================
   EXPORTS
   ============================================================ */

module.exports = {

  submitTx,

  getPBFTMetrics,

  getBlockchainLength,

  validateBlockchainFile

};
