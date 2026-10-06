
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
YOLOChain
Experiment D:
YOLOv8 + MQTT + PQC + PBFT-style Blockchain

E2E-aware experimental version.

IMPORTANT MEASUREMENT DEFINITIONS
----------------------------------
1. YOLO inference:
   Detector inference only.

2. Post-processing:
   Processing of YOLO outputs after inference.

3. JSON generation:
   Construction of the signed metadata message.

4. PQC signing:
   Local PQC signature operation.

5. MQTT transmission:
   MQTT publish/wait interval measured by the camera process.
   This is NOT interpreted as pure network propagation latency.

6. PBFT latency:
   PBFT start -> canonical PBFT commit, taken from the validator
   pbft_metrics.csv.

7. Block write:
   Local block persistence time reported by the validator.

8. Consensus-to-disk:
   Consensus start -> local block persistence, reported by validator.

9. END-TO-END LATENCY:
   Original camera/source timestamp
       ->
   canonical PBFT commit timestamp

   E2E is measured directly from timestamps.
   It is NOT calculated as a sum of component latencies.

10. Recovery:
    A recovery transaction receives a NEW transaction ID.
    It is still associated with the ORIGINAL source event.
    Recovery transactions are not counted as additional source frames.

11. Equivalent FPS:
       1000 / mean E2E latency_ms

    This is a descriptive equivalent rate, NOT measured sustained
    throughput.

PBFT CSV EXPECTED FORMAT
------------------------
validator_id
node_id
commit_timestamp
block_index
tx_id
...
tx_submission_timestamp
pbft_start_timestamp
...
block_append_timestamp
pbft_preprepare_ms
pbft_prepare_ms
pbft_commit_phase_ms
pbft_latency_ms
transaction_commit_latency_ms
block_write_ms
total_consensus_to_disk_ms
committed_tps

The canonical PBFT CSV is:
    results_D/validator_1/results/pbft_metrics.csv
"""

import argparse
import base64
import csv
import ctypes
import json
import os
import platform
import statistics
import time
import uuid

from datetime import datetime, timezone
from pathlib import Path

import cv2
import paho.mqtt.client as mqtt
import torch
from ultralytics import YOLO


# ============================================================
# ARGUMENTS
# ============================================================

parser = argparse.ArgumentParser(
    description="YOLOChain Experiment D - E2E-aware camera pipeline"
)

parser.add_argument("--dataset", choices=["coco128", "mot17"], required=True)
parser.add_argument("--input-dir", required=True)
parser.add_argument("--camera-id", default="camera_01")
parser.add_argument("--sequence", default=None)

parser.add_argument("--model", default="yolov8n.pt")
parser.add_argument("--img-size", type=int, default=416)
parser.add_argument("--conf", type=float, default=0.25)
parser.add_argument("--iou", type=float, default=0.50)

parser.add_argument("--target-fps", type=float, default=0)

parser.add_argument("--broker", default="localhost")
parser.add_argument("--port", type=int, default=1883)
parser.add_argument("--topic", default="pqc/handshake")

parser.add_argument("--algo-code", default="2")
parser.add_argument("--algo-name", default="falcon-512")
parser.add_argument("--pqc-library", default="./r1_sign_lib.so")

parser.add_argument("--results-dir", default="results_D")

parser.add_argument(
    "--pbft-metrics-file",
    default="results_D/validator_1/results/pbft_metrics.csv"
)

parser.add_argument("--pbft-timeout", type=float, default=20.0)
parser.add_argument("--pbft-poll", type=float, default=0.25)

parser.add_argument("--max-retries", type=int, default=100)
parser.add_argument("--recovery-timeout", type=float, default=10.0)

parser.add_argument("--max-images", type=int, default=0)
parser.add_argument("--runs", type=int, default=5)

parser.add_argument("--no-display", action="store_true")

args = parser.parse_args()


# ============================================================
# CONFIGURATION
# ============================================================

DATASET_NAME = (
    "MOT17"
    if args.dataset == "mot17"
    else "COCO128"
)

CAMERA_ID = args.camera_id
SEQUENCE_NAME = args.sequence

IMAGE_FOLDER = Path(args.input_dir)

MODEL_PATH = args.model
IMG_SIZE = args.img_size

CONF_THRESHOLD = args.conf
IOU_THRESHOLD = args.iou

TARGET_FPS = args.target_fps

MQTT_BROKER = args.broker
MQTT_PORT = args.port
MQTT_TOPIC = args.topic

PQC_LIBRARY = args.pqc_library
PQC_ALGO_CODE = args.algo_code.encode("ascii")
PQC_ALGO_NAME = args.algo_name

PBFT_METRICS_FILE = Path(args.pbft_metrics_file)

PBFT_TIMEOUT = args.pbft_timeout
PBFT_POLL_INTERVAL = args.pbft_poll

MAX_RECOVERY_RETRIES = args.max_retries
RECOVERY_TIMEOUT = args.recovery_timeout

RUNS = args.runs

if RUNS < 1:
    raise ValueError("--runs must be >= 1")


# ============================================================
# RESULT DIRECTORIES
# ============================================================

RESULTS_ROOT = Path(args.results_dir)

CAMERA_RESULTS_DIR = RESULTS_ROOT / "camera" / CAMERA_ID
CAMERA_RESULTS_DIR.mkdir(parents=True, exist_ok=True)


CSV_PATH = CAMERA_RESULTS_DIR / "camera_metrics.csv"
SUMMARY_CSV_PATH = CAMERA_RESULTS_DIR / "camera_summary.csv"
METADATA_PATH = CAMERA_RESULTS_DIR / "experiment_metadata.json"
FAILED_CSV_PATH = CAMERA_RESULTS_DIR / "failed_frames.csv"
PBFT_RESULT_PATH = CAMERA_RESULTS_DIR / "pbft_commit_summary.csv"
RUN_SUMMARY_PATH = CAMERA_RESULTS_DIR / "run_summary.csv"

# NEW: direct source -> canonical commit measurements
E2E_METRICS_PATH = CAMERA_RESULTS_DIR / "e2e_metrics.csv"
E2E_RUN_SUMMARY_PATH = CAMERA_RESULTS_DIR / "e2e_run_summary.csv"


IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".webp"
}


# ============================================================
# TIMING HELPERS
# ============================================================

def now():
    return time.perf_counter()


def epoch_ms():
    return int(time.time() * 1000)


def ms(seconds):
    return round(seconds * 1000.0, 3)


def percentile_ms(values_ms, p):
    """
    Percentile for values already expressed in milliseconds.
    """
    if not values_ms:
        return 0.0

    ordered = sorted(float(v) for v in values_ms)

    if len(ordered) == 1:
        return ordered[0]

    k = (len(ordered) - 1) * (p / 100.0)

    f = int(k)
    c = min(f + 1, len(ordered) - 1)

    if f == c:
        return ordered[f]

    return (
        ordered[f]
        + (ordered[c] - ordered[f]) * (k - f)
    )


def statistics_summary_ms(values_ms):
    """
    Summary of frame/transaction observations in milliseconds.
    """
    values = [float(v) for v in values_ms if v is not None]

    if not values:
        return {
            "mean_ms": 0.0,
            "median_ms": 0.0,
            "std_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "min_ms": 0.0,
            "max_ms": 0.0
        }

    return {
        "mean_ms": statistics.mean(values),
        "median_ms": statistics.median(values),
        "std_ms": (
            statistics.stdev(values)
            if len(values) > 1
            else 0.0
        ),
        "p95_ms": percentile_ms(values, 95),
        "p99_ms": percentile_ms(values, 99),
        "min_ms": min(values),
        "max_ms": max(values)
    }


# ============================================================
# TIMESTAMP CONVERSION
# ============================================================

def parse_epoch_ms(value):
    """
    Convert a PBFT timestamp represented as epoch milliseconds
    or a numeric string into float milliseconds.
    """
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    try:
        return float(text)
    except ValueError:
        return None


def parse_iso_timestamp_ms(value):
    """
    Convert ISO-8601 timestamp to epoch milliseconds.

    Example:
        2026-10-01T13:41:10.412Z
    """
    if value is None:
        return None

    text = str(value).strip()

    if not text:
        return None

    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.timestamp() * 1000.0

    except Exception:
        return None


def parse_pbft_commit_timestamp_ms(row):
    """
    PBFT canonical commit timestamp is normally ISO-8601.
    """
    value = row.get("commit_timestamp")

    parsed = parse_iso_timestamp_ms(value)

    if parsed is not None:
        return parsed

    return parse_epoch_ms(value)


# ============================================================
# FAILURE HANDLING
# ============================================================

failed_records = []


def record_failure(
    run_id,
    image_index,
    image_path,
    transaction_id,
    stage,
    error,
    frame_id=None
):
    failed_records.append(
        {
            "run_id": run_id,
            "image_index": image_index,
            "image": (
                image_path.name
                if image_path is not None
                else ""
            ),
            "frame_id": (
                frame_id
                if frame_id is not None
                else ""
            ),
            "transaction_id": (
                transaction_id
                if transaction_id is not None
                else ""
            ),
            "stage": stage,
            "error": str(error),
            "timestamp_ms": epoch_ms()
        }
    )

    print(
        f"❌ Run {run_id} | "
        f"Image {image_index} | "
        f"Stage={stage} | "
        f"Error={error}"
    )


# ============================================================
# PBFT CSV READER
# ============================================================

def read_pbft_rows(metrics_file):
    """
    Read canonical validator-1 PBFT metrics.

    IMPORTANT:
    The CSV uses tx_id, not transaction_id.
    """
    metrics_file = Path(metrics_file)

    if not metrics_file.exists():
        return []

    rows = []

    try:
        with open(
            metrics_file,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(file)

            for row in reader:
                rows.append(row)

    except Exception as error:
        print(
            "⚠️ Could not read PBFT metrics:",
            error
        )

    return rows


def read_committed_transaction_ids(metrics_file):
    rows = read_pbft_rows(metrics_file)

    committed = set()

    for row in rows:
        tx_id = (
            row.get("tx_id")
            or row.get("transaction_id")
        )

        if tx_id:
            committed.add(str(tx_id).strip())

    return committed


def build_pbft_index(metrics_file):
    """
    Build:
        tx_id -> canonical PBFT row

    If duplicate rows exist, the latest row in the file is retained.
    """
    rows = read_pbft_rows(metrics_file)

    index = {}

    for row in rows:
        tx_id = (
            row.get("tx_id")
            or row.get("transaction_id")
        )

        if tx_id:
            index[str(tx_id).strip()] = row

    return index


# ============================================================
# WAIT FOR PBFT
# ============================================================

def wait_for_pbft_completion(
    submitted_tx_ids,
    metrics_file,
    timeout_sec,
    poll_interval
):
    submitted = set(submitted_tx_ids)

    if not submitted:
        return set(), set(), 0.0

    start = now()

    while True:

        committed = read_committed_transaction_ids(
            metrics_file
        )

        matched = submitted & committed
        missing = submitted - committed

        if not missing:
            elapsed = now() - start

            print(
                f"✅ PBFT completion: "
                f"{len(matched)}/{len(submitted)}"
            )

            return matched, missing, elapsed

        elapsed = now() - start

        if elapsed >= timeout_sec:

            print(
                f"⚠️ PBFT timeout: "
                f"{len(matched)}/{len(submitted)} "
                f"committed"
            )

            return matched, missing, elapsed

        time.sleep(poll_interval)


# ============================================================
# E2E EXTRACTION
# ============================================================

def extract_e2e_record(
    tx_id,
    source_timestamp_ms,
    pbft_row,
    run_id,
    original_transaction_id=None,
    recovery_transaction_id=None
):
    """
    Calculate direct source -> canonical PBFT commit E2E.

    E2E = canonical commit timestamp - original source timestamp.

    No component summation is performed.
    """

    if pbft_row is None:
        return None

    commit_timestamp_ms = parse_pbft_commit_timestamp_ms(
        pbft_row
    )

    if source_timestamp_ms is None:
        return None

    if commit_timestamp_ms is None:
        return None

    e2e_ms = (
        commit_timestamp_ms
        - float(source_timestamp_ms)
    )

    return {
        "run_id": run_id,
        "source_transaction_id": (
            original_transaction_id
            if original_transaction_id is not None
            else tx_id
        ),
        "committed_transaction_id": tx_id,
        "recovery_transaction_id": (
            recovery_transaction_id
            if recovery_transaction_id is not None
            else ""
        ),
        "source_timestamp_ms": (
            float(source_timestamp_ms)
        ),
        "pbft_submission_timestamp_ms": (
            parse_epoch_ms(
                pbft_row.get(
                    "tx_submission_timestamp"
                )
            )
        ),
        "pbft_start_timestamp_ms": (
            parse_epoch_ms(
                pbft_row.get(
                    "pbft_start_timestamp"
                )
            )
        ),
        "commit_timestamp_ms": (
            commit_timestamp_ms
        ),
        "e2e_latency_ms": e2e_ms,
        "pbft_latency_ms": (
            float(pbft_row["pbft_latency_ms"])
            if pbft_row.get("pbft_latency_ms")
            else ""
        ),
        "transaction_commit_latency_ms": (
            float(
                pbft_row[
                    "transaction_commit_latency_ms"
                ]
            )
            if pbft_row.get(
                "transaction_commit_latency_ms"
            )
            else ""
        ),
        "block_write_ms": (
            float(pbft_row["block_write_ms"])
            if pbft_row.get("block_write_ms")
            else ""
        ),
        "total_consensus_to_disk_ms": (
            float(
                pbft_row[
                    "total_consensus_to_disk_ms"
                ]
            )
            if pbft_row.get(
                "total_consensus_to_disk_ms"
            )
            else ""
        ),
        "camera_id": (
            pbft_row.get("camera_id", CAMERA_ID)
        ),
        "dataset": (
            pbft_row.get("dataset", DATASET_NAME)
        ),
        "frame_id": (
            pbft_row.get("frame_id", "")
        ),
        "image_index": (
            pbft_row.get("image_index", "")
        ),
        "commit_status": "committed"
    }


# ============================================================
# PQC SIGNING
# ============================================================

def sign_message_dict(message_obj):

    message_bytes = json.dumps(
        message_obj,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    sig_ptr = ctypes.POINTER(
        ctypes.c_ubyte
    )()

    pk_ptr = ctypes.POINTER(
        ctypes.c_ubyte
    )()

    sig_len = ctypes.c_size_t()
    pk_len = ctypes.c_size_t()

    ret = lib.pqc_sign(
        message_bytes,
        len(message_bytes),
        PQC_ALGO_CODE,
        ctypes.byref(sig_ptr),
        ctypes.byref(sig_len),
        ctypes.byref(pk_ptr),
        ctypes.byref(pk_len)
    )

    if ret != 0:
        raise RuntimeError(
            f"pqc_sign returned error code {ret}"
        )

    try:

        signature = ctypes.string_at(
            sig_ptr,
            sig_len.value
        )

        public_key = ctypes.string_at(
            pk_ptr,
            pk_len.value
        )

    finally:

        if bool(sig_ptr):
            try:
                lib.pqc_free(sig_ptr)
            except Exception:
                pass

    return message_bytes, signature, public_key


# ============================================================
# MQTT
# ============================================================

MQTT_CLIENT_ID = (
    f"yolo-{CAMERA_ID}-{uuid.uuid4().hex[:8]}"
)

mqtt_connected = False


def on_connect(client_obj, userdata, flags, rc):
    global mqtt_connected

    mqtt_connected = (rc == 0)

    if mqtt_connected:
        print(
            f"🟢 MQTT connected | "
            f"Client ID: {MQTT_CLIENT_ID}"
        )
    else:
        print(
            f"❌ MQTT connection failed | rc={rc}"
        )


def on_disconnect(client_obj, userdata, rc):
    global mqtt_connected

    mqtt_connected = False

    print(
        f"⚠️ MQTT disconnected | rc={rc}"
    )


def publish_payload(payload):

    if not client.is_connected():

        try:
            client.reconnect()
        except Exception:
            pass

        deadline = time.time() + 5

        while (
            not client.is_connected()
            and
            time.time() < deadline
        ):
            time.sleep(0.05)

    if not client.is_connected():
        return False

    payload_json = json.dumps(
        payload,
        separators=(",", ":")
    )

    info = client.publish(
        MQTT_TOPIC,
        payload_json,
        qos=1,
        retain=False
    )

    info.wait_for_publish()

    return (
        info.rc == mqtt.MQTT_ERR_SUCCESS
    )


# ============================================================
# RECOVERY
# ============================================================

def create_recovery_payload(
    original_payload,
    original_transaction_id,
    attempt,
    run_id
):

    original_message_bytes = base64.b64decode(
        original_payload["message_b64"]
    )

    original_message = json.loads(
        original_message_bytes.decode("utf-8")
    )

    recovery_transaction_id = uuid.uuid4().hex

    recovery_message = dict(original_message)

    recovery_message["transaction_id"] = (
        recovery_transaction_id
    )

    recovery_message["recovery_of"] = (
        original_transaction_id
    )

    recovery_message["recovery_attempt"] = attempt
    recovery_message["recovery_run_id"] = run_id
    recovery_message["recovery_timestamp_ms"] = epoch_ms()
    recovery_message["recovery_timestamp"] = (
        datetime.now(timezone.utc).isoformat()
    )

    (
        message_bytes,
        signature,
        public_key
    ) = sign_message_dict(
        recovery_message
    )

    recovery_payload = {
        "transaction_id":
            recovery_transaction_id,

        "message_b64":
            base64.b64encode(
                message_bytes
            ).decode("utf-8"),

        "signature_b64":
            base64.b64encode(
                signature
            ).decode("utf-8"),

        "public_key_b64":
            base64.b64encode(
                public_key
            ).decode("utf-8"),

        "algo": PQC_ALGO_NAME,
        "algo_name": PQC_ALGO_NAME,
        "algo_code": args.algo_code,

        "camera_id": CAMERA_ID,
        "dataset": DATASET_NAME,
        "sequence": SEQUENCE_NAME,

        "model": MODEL_PATH,
        "img_size": IMG_SIZE,
        "conf_threshold": CONF_THRESHOLD,
        "iou_threshold": IOU_THRESHOLD,

        "timestamp_ms":
            original_payload.get(
                "timestamp_ms"
            ),

        "run_id": run_id,

        "timing":
            original_payload.get(
                "timing",
                {}
            ),

        "recovery_of":
            original_transaction_id,

        "recovery_attempt":
            attempt,

        "recovery_run_id":
            run_id
    }

    return (
        recovery_transaction_id,
        recovery_payload
    )


def recover_missing_as_new_transactions(
    initial_missing_ids,
    submitted_payloads,
    source_timestamp_by_tx,
    max_retries,
    recovery_timeout,
    poll_interval,
    run_id
):

    remaining = set(initial_missing_ids)

    recovery_transaction_ids = []
    recovered_original_ids = set()
    recovery_history = []

    latest_tx_by_original = {}

    recovery_start = now()

    for attempt in range(1, max_retries + 1):

        if not remaining:
            break

        print()
        print("=" * 80)
        print(
            f"RECOVERY RUN {run_id} | "
            f"ATTEMPT {attempt}"
        )
        print("=" * 80)

        attempt_tx_ids = []

        for original_id in sorted(remaining):

            original_payload = submitted_payloads.get(
                original_id
            )

            if original_payload is None:
                continue

            try:

                (
                    recovery_tx_id,
                    recovery_payload
                ) = create_recovery_payload(
                    original_payload,
                    original_id,
                    attempt,
                    run_id
                )

                published = publish_payload(
                    recovery_payload
                )

                if published:

                    attempt_tx_ids.append(
                        recovery_tx_id
                    )

                    recovery_transaction_ids.append(
                        recovery_tx_id
                    )

                    latest_tx_by_original[
                        original_id
                    ] = recovery_tx_id

                    recovery_history.append(
                        {
                            "run_id": run_id,
                            "original_transaction_id":
                                original_id,
                            "recovery_attempt":
                                attempt,
                            "recovery_transaction_id":
                                recovery_tx_id,
                            "published": True,
                            "committed": False
                        }
                    )

                    print(
                        f"📤 Recovery submitted | "
                        f"original={original_id} | "
                        f"new={recovery_tx_id}"
                    )

            except Exception as error:

                recovery_history.append(
                    {
                        "run_id": run_id,
                        "original_transaction_id":
                            original_id,
                        "recovery_attempt":
                            attempt,
                        "recovery_transaction_id":
                            "",
                        "published": False,
                        "committed": False,
                        "error": str(error)
                    }
                )

        if attempt_tx_ids:

            (
                committed,
                missing,
                _
            ) = wait_for_pbft_completion(
                attempt_tx_ids,
                PBFT_METRICS_FILE,
                recovery_timeout,
                poll_interval
            )

            committed = set(committed)

            for record in recovery_history:

                tx = record.get(
                    "recovery_transaction_id"
                )

                if tx in committed:
                    record["committed"] = True

                    recovered_original_ids.add(
                        record[
                            "original_transaction_id"
                        ]
                    )

            remaining -= recovered_original_ids

        print(
            f"Remaining after attempt {attempt}: "
            f"{len(remaining)}"
        )

    return {
        "recovery_transaction_ids":
            recovery_transaction_ids,

        "recovered_original_ids":
            recovered_original_ids,

        "remaining_original_ids":
            remaining,

        "recovery_history":
            recovery_history,

        "latest_tx_by_original":
            latest_tx_by_original,

        "recovery_time_sec":
            now() - recovery_start
    }


# ============================================================
# INFORMATION
# ============================================================

print()
print("=" * 90)
print("YOLOCHAIN EXPERIMENT D")
print("E2E-AWARE CAMERA + PQC + MQTT + PBFT")
print("=" * 90)

print("Camera ID        :", CAMERA_ID)
print("Dataset          :", DATASET_NAME)
print("Sequence         :", SEQUENCE_NAME)
print("Input directory  :", IMAGE_FOLDER)
print("Model            :", MODEL_PATH)
print("Image size       :", IMG_SIZE)
print("Confidence       :", CONF_THRESHOLD)
print("IoU threshold    :", IOU_THRESHOLD)
print("Warm-ups         :", 10)
print("Independent runs :", RUNS)
print("PQC algorithm    :", PQC_ALGO_NAME)
print("PQC code         :", args.algo_code)
print("PQC library      :", PQC_LIBRARY)
print("MQTT broker      :", MQTT_BROKER)
print("MQTT port        :", MQTT_PORT)
print("MQTT topic       :", MQTT_TOPIC)
print("PBFT metrics     :", PBFT_METRICS_FILE)
print("PBFT timeout     :", PBFT_TIMEOUT, "sec")
print("Max recovery     :", MAX_RECOVERY_RETRIES)
print("Recovery timeout :", RECOVERY_TIMEOUT, "sec/round")
print("Results directory:", RESULTS_ROOT)
print("=" * 90)


# ============================================================
# VALIDATE INPUT
# ============================================================

if not IMAGE_FOLDER.exists():
    raise FileNotFoundError(
        f"Image folder does not exist:\n{IMAGE_FOLDER}"
    )

if not IMAGE_FOLDER.is_dir():
    raise NotADirectoryError(
        f"Input path is not a directory:\n{IMAGE_FOLDER}"
    )

image_files = sorted(
    [
        path
        for path in IMAGE_FOLDER.iterdir()
        if (
            path.is_file()
            and path.suffix.lower()
            in IMAGE_EXTENSIONS
        )
    ]
)

if args.max_images > 0:
    image_files = image_files[:args.max_images]

if not image_files:
    raise RuntimeError(
        "No supported images were found."
    )

print()
print(
    f"Found {len(image_files)} images/frames"
)


# ============================================================
# DEVICE
# ============================================================

device = (
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

half = device == "cuda"

print("Device           :", device)
print("FP16             :", half)


def synchronize_cuda():

    if (
        device == "cuda"
        and
        torch.cuda.is_available()
    ):
        torch.cuda.synchronize()


# ============================================================
# MQTT CONNECTION
# ============================================================

client = mqtt.Client(
    client_id=MQTT_CLIENT_ID
)

client.on_connect = on_connect
client.on_disconnect = on_disconnect

client.reconnect_delay_set(
    min_delay=1,
    max_delay=10
)

print()
print("Connecting to MQTT...")

client.connect(
    MQTT_BROKER,
    MQTT_PORT,
    keepalive=60
)

client.loop_start()

deadline = time.time() + 10

while (
    not mqtt_connected
    and
    time.time() < deadline
):
    time.sleep(0.05)

if not mqtt_connected:
    client.loop_stop()
    raise RuntimeError(
        "Unable to connect to MQTT broker"
    )


# ============================================================
# PQC LIBRARY
# ============================================================

if not Path(PQC_LIBRARY).exists():

    client.loop_stop()

    raise FileNotFoundError(
        f"PQC shared library not found:\n{PQC_LIBRARY}"
    )

lib = ctypes.CDLL(PQC_LIBRARY)

lib.pqc_sign.argtypes = [
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char,
    ctypes.POINTER(
        ctypes.POINTER(ctypes.c_ubyte)
    ),
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.POINTER(
        ctypes.POINTER(ctypes.c_ubyte)
    ),
    ctypes.POINTER(ctypes.c_size_t)
]

lib.pqc_sign.restype = ctypes.c_int

lib.pqc_free.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte)
]

lib.pqc_free.restype = None

print("✅ PQC library loaded")


# ============================================================
# YOLO
# ============================================================

print()
print("🔥 Loading YOLO model...")

model_load_start = now()

model = YOLO(MODEL_PATH)
model.to(device)

synchronize_cuda()

model_load_time = now() - model_load_start

print(
    "✅ YOLO model loaded in",
    ms(model_load_time),
    "ms"
)


# ============================================================
# WARM-UP
# ============================================================

warmup_image = cv2.imread(
    str(image_files[0])
)

if warmup_image is not None:

    print()
    print("🔥 YOLO warm-up: 10 iterations...")

    for _ in range(10):

        model.predict(
            warmup_image,
            device=device,
            imgsz=IMG_SIZE,
            conf=CONF_THRESHOLD,
            iou=IOU_THRESHOLD,
            half=half,
            verbose=False
        )

        synchronize_cuda()

    print("✅ Warm-up completed")


# ============================================================
# CSV FILES
# ============================================================

CSV_FIELDS = [
    "run_id",
    "status",
    "failure_stage",
    "error_message",
    "transaction_id",

    "source_timestamp_ms",
    "source_timestamp_iso",

    "camera_id",
    "dataset",
    "sequence",

    "image_index",
    "frame_id",
    "image",
    "detection_count",

    "yolo_inference_ms",
    "postprocessing_ms",
    "json_generation_ms",
    "pqc_signing_ms",
    "mqtt_transmission_ms",
    "python_pipeline_ms",

    "model",
    "image_size",
    "confidence_threshold",
    "iou_threshold",
    "device",
    "fp16"
]

csv_file = open(
    CSV_PATH,
    "w",
    newline="",
    encoding="utf-8"
)

csv_writer = csv.DictWriter(
    csv_file,
    fieldnames=CSV_FIELDS
)

csv_writer.writeheader()


summary_file = open(
    SUMMARY_CSV_PATH,
    "w",
    newline="",
    encoding="utf-8"
)

summary_writer = csv.DictWriter(
    summary_file,
    fieldnames=[
        "run_id",
        "component",
        "mean_ms",
        "median_ms",
        "std_ms",
        "p95_ms",
        "p99_ms",
        "min_ms",
        "max_ms"
    ]
)

summary_writer.writeheader()


run_summary_file = open(
    RUN_SUMMARY_PATH,
    "w",
    newline="",
    encoding="utf-8"
)

run_summary_writer = csv.DictWriter(
    run_summary_file,
    fieldnames=[
        "run_id",
        "images_available",
        "images_processed",
        "images_failed",
        "transactions_submitted",
        "initial_committed",
        "initial_missing",
        "recovery_transactions",
        "recovered_originals",
        "final_missing_originals",
        "pbft_drain_sec",
        "recovery_time_sec",
        "experiment_time_sec",
        "python_throughput_fps",
        "detection_rate_per_sec"
    ]
)

run_summary_writer.writeheader()


pbft_summary_file = open(
    PBFT_RESULT_PATH,
    "w",
    newline="",
    encoding="utf-8"
)

pbft_writer = csv.DictWriter(
    pbft_summary_file,
    fieldnames=[
        "run_id",
        "original_transaction_id",
        "initially_committed",
        "initially_missing",
        "recovery_attempt",
        "recovery_transaction_id",
        "recovery_published",
        "recovery_committed",
        "final_status"
    ]
)

pbft_writer.writeheader()


# ============================================================
# NEW: E2E CSV
# ============================================================

E2E_FIELDS = [
    "run_id",
    "source_transaction_id",
    "committed_transaction_id",
    "recovery_transaction_id",

    "source_timestamp_ms",
    "pbft_submission_timestamp_ms",
    "pbft_start_timestamp_ms",
    "commit_timestamp_ms",

    "e2e_latency_ms",

    "pbft_latency_ms",
    "transaction_commit_latency_ms",
    "block_write_ms",
    "total_consensus_to_disk_ms",

    "camera_id",
    "dataset",
    "frame_id",
    "image_index",

    "commit_status"
]

e2e_file = open(
    E2E_METRICS_PATH,
    "w",
    newline="",
    encoding="utf-8"
)

e2e_writer = csv.DictWriter(
    e2e_file,
    fieldnames=E2E_FIELDS
)

e2e_writer.writeheader()


E2E_RUN_FIELDS = [
    "run_id",
    "source_events",
    "canonical_committed_events",
    "recovered_events",
    "missing_events",

    "e2e_mean_ms",
    "e2e_median_ms",
    "e2e_std_ms",
    "e2e_p95_ms",
    "e2e_p99_ms",
    "e2e_min_ms",
    "e2e_max_ms",

    "equivalent_fps",

    "completion_rate_percent"
]

e2e_run_file = open(
    E2E_RUN_SUMMARY_PATH,
    "w",
    newline="",
    encoding="utf-8"
)

e2e_run_writer = csv.DictWriter(
    e2e_run_file,
    fieldnames=E2E_RUN_FIELDS
)

e2e_run_writer.writeheader()


# ============================================================
# GLOBAL STATE
# ============================================================

all_run_metadata = []

global_start = now()


# ============================================================
# MAIN RUN LOOP
# ============================================================

try:

    for run_id in range(1, RUNS + 1):

        print()
        print("=" * 90)
        print(
            f"STARTING INDEPENDENT RUN "
            f"{run_id}/{RUNS}"
        )
        print("=" * 90)

        run_start = now()

        inference_times = []
        postprocess_times = []
        json_times = []
        pqc_times = []
        mqtt_times = []
        pipeline_times = []

        processed_images = 0
        failed_images = 0
        total_detections = 0

        submitted_transaction_ids = []

        submitted_payloads = {}

        # Original source timestamp for every original TX.
        source_timestamp_by_tx = {}

        # Image metadata for E2E reporting.
        source_metadata_by_tx = {}

        transaction_id_set = set()

        mqtt_publish_failures = 0

        user_stopped = False

        # ====================================================
        # IMAGE LOOP
        # ====================================================

        for image_index, image_path in enumerate(
            image_files,
            start=1
        ):

            print()
            print("-" * 90)

            print(
                f"[Run {run_id}/{RUNS}] "
                f"[{image_index}/{len(image_files)}] "
                f"{image_path.name}"
            )

            pipeline_start = now()

            transaction_id = None

            frame_id = None

            source_timestamp_ms = None
            source_timestamp_iso = None

            inference_time = 0.0
            post_time = 0.0
            json_time = 0.0
            pqc_time = 0.0
            mqtt_time = 0.0

            detection_count = 0

            # ------------------------------------------------
            # READ
            # ------------------------------------------------

            try:

                frame = cv2.imread(
                    str(image_path)
                )

            except Exception as error:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    None,
                    "image_read",
                    error
                )

                continue

            if frame is None:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    None,
                    "image_read",
                    "cv2.imread returned None"
                )

                continue

            # ------------------------------------------------
            # FRAME ID
            # ------------------------------------------------

            if args.dataset == "mot17":

                try:
                    frame_id = int(
                        image_path.stem
                    )
                except ValueError:
                    frame_id = image_index

            # ------------------------------------------------
            # TX ID
            # ------------------------------------------------

            transaction_id = uuid.uuid4().hex

            if transaction_id in transaction_id_set:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    transaction_id,
                    "transaction_id",
                    "Duplicate transaction ID",
                    frame_id
                )

                continue

            transaction_id_set.add(
                transaction_id
            )

            # ------------------------------------------------
            # SOURCE TIMESTAMP
            # ------------------------------------------------

            source_timestamp_ms = epoch_ms()

            source_timestamp_iso = (
                datetime.now(
                    timezone.utc
                ).isoformat()
            )

            # ------------------------------------------------
            # YOLO INFERENCE
            # ------------------------------------------------

            try:

                synchronize_cuda()

                t0 = now()

                results = model.predict(
                    frame,
                    device=device,
                    imgsz=IMG_SIZE,
                    conf=CONF_THRESHOLD,
                    iou=IOU_THRESHOLD,
                    half=half,
                    verbose=False
                )

                synchronize_cuda()

                inference_time = now() - t0

            except Exception as error:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    transaction_id,
                    "yolo_inference",
                    error,
                    frame_id
                )

                continue

            # ------------------------------------------------
            # POST-PROCESSING
            # ------------------------------------------------

            try:

                t0 = now()

                result = results[0]

                detections = []

                for box in result.boxes:

                    cls_id = int(
                        box.cls[0]
                    )

                    confidence = float(
                        box.conf[0]
                    )

                    x1, y1, x2, y2 = map(
                        float,
                        box.xyxy[0]
                    )

                    detections.append(
                        {
                            "class_id": cls_id,
                            "class":
                                result.names[cls_id],
                            "confidence":
                                round(
                                    confidence,
                                    6
                                ),
                            "bbox":
                                {
                                    "x1":
                                        round(
                                            x1,
                                            2
                                        ),
                                    "y1":
                                        round(
                                            y1,
                                            2
                                        ),
                                    "x2":
                                        round(
                                            x2,
                                            2
                                        ),
                                    "y2":
                                        round(
                                            y2,
                                            2
                                        )
                                }
                        }
                    )

                detection_count = len(
                    detections
                )

                post_time = now() - t0

            except Exception as error:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    transaction_id,
                    "postprocessing",
                    error,
                    frame_id
                )

                continue

            # ------------------------------------------------
            # JSON GENERATION
            # ------------------------------------------------

            try:

                t0 = now()

                message = {
                    "schema_version": "1.1",
                    "transaction_id":
                        transaction_id,

                    "camera_id":
                        CAMERA_ID,

                    "dataset":
                        DATASET_NAME,

                    "sequence":
                        SEQUENCE_NAME,

                    "timestamp":
                        source_timestamp_iso,

                    "timestamp_ms":
                        source_timestamp_ms,

                    "image":
                        image_path.name,

                    "image_index":
                        image_index,

                    "run_id":
                        run_id,

                    "frame_id":
                        frame_id,

                    "frame_file":
                        image_path.name,

                    "detection_count":
                        detection_count,

                    "detections":
                        detections,

                    "model":
                        MODEL_PATH,

                    "img_size":
                        IMG_SIZE,

                    "conf_threshold":
                        CONF_THRESHOLD,

                    "iou_threshold":
                        IOU_THRESHOLD,

                    "timing":
                        {
                            "yolo_inference_ms":
                                ms(inference_time),

                            "postprocessing_ms":
                                ms(post_time)
                        }
                }

                message_bytes = json.dumps(
                    message,
                    sort_keys=True,
                    separators=(",", ":")
                ).encode("utf-8")

                json_time = now() - t0

            except Exception as error:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    transaction_id,
                    "json_generation",
                    error,
                    frame_id
                )

                continue

            # ------------------------------------------------
            # PQC SIGNING
            # ------------------------------------------------

            sig_ptr = ctypes.POINTER(
                ctypes.c_ubyte
            )()

            pk_ptr = ctypes.POINTER(
                ctypes.c_ubyte
            )()

            sig_len = ctypes.c_size_t()
            pk_len = ctypes.c_size_t()

            try:

                t0 = now()

                ret = lib.pqc_sign(
                    message_bytes,
                    len(message_bytes),
                    PQC_ALGO_CODE,
                    ctypes.byref(sig_ptr),
                    ctypes.byref(sig_len),
                    ctypes.byref(pk_ptr),
                    ctypes.byref(pk_len)
                )

                pqc_time = now() - t0

                if ret != 0:
                    raise RuntimeError(
                        f"pqc_sign returned {ret}"
                    )

                signature = ctypes.string_at(
                    sig_ptr,
                    sig_len.value
                )

                public_key = ctypes.string_at(
                    pk_ptr,
                    pk_len.value
                )

            except Exception as error:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    transaction_id,
                    "pqc_signing",
                    error,
                    frame_id
                )

                continue

            finally:

                try:

                    if bool(sig_ptr):
                        lib.pqc_free(sig_ptr)

                except Exception:
                    pass

            # ------------------------------------------------
            # MQTT PAYLOAD
            # ------------------------------------------------

            try:

                payload = {
                    "transaction_id":
                        transaction_id,

                    "message_b64":
                        base64.b64encode(
                            message_bytes
                        ).decode("utf-8"),

                    "signature_b64":
                        base64.b64encode(
                            signature
                        ).decode("utf-8"),

                    "public_key_b64":
                        base64.b64encode(
                            public_key
                        ).decode("utf-8"),

                    "algo":
                        PQC_ALGO_NAME,

                    "algo_name":
                        PQC_ALGO_NAME,

                    "algo_code":
                        args.algo_code,

                    "camera_id":
                        CAMERA_ID,

                    "dataset":
                        DATASET_NAME,

                    "sequence":
                        SEQUENCE_NAME,

                    "model":
                        MODEL_PATH,

                    "img_size":
                        IMG_SIZE,

                    "conf_threshold":
                        CONF_THRESHOLD,

                    "iou_threshold":
                        IOU_THRESHOLD,

                    "timestamp_ms":
                        source_timestamp_ms,

                    "run_id":
                        run_id,

                    "timing":
                        {
                            "yolo_inference_ms":
                                ms(inference_time),

                            "postprocessing_ms":
                                ms(post_time),

                            "json_generation_ms":
                                ms(json_time),

                            "pqc_signing_ms":
                                ms(pqc_time)
                        }
                }

                payload_json = json.dumps(
                    payload,
                    separators=(",", ":")
                )

            except Exception as error:

                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    transaction_id,
                    "mqtt_payload",
                    error,
                    frame_id
                )

                continue

            # ------------------------------------------------
            # MQTT
            # ------------------------------------------------

            try:

                t0 = now()

                if not client.is_connected():

                    try:
                        client.reconnect()
                    except Exception:
                        pass

                    deadline = time.time() + 5

                    while (
                        not client.is_connected()
                        and
                        time.time() < deadline
                    ):
                        time.sleep(0.05)

                if not client.is_connected():

                    raise RuntimeError(
                        "MQTT is not connected"
                    )

                info = client.publish(
                    MQTT_TOPIC,
                    payload_json,
                    qos=1,
                    retain=False
                )

                info.wait_for_publish()

                if (
                    info.rc
                    !=
                    mqtt.MQTT_ERR_SUCCESS
                ):
                    raise RuntimeError(
                        f"MQTT publish rc={info.rc}"
                    )

                mqtt_time = now() - t0

            except Exception as error:

                mqtt_publish_failures += 1
                failed_images += 1

                record_failure(
                    run_id,
                    image_index,
                    image_path,
                    transaction_id,
                    "mqtt_publish",
                    error,
                    frame_id
                )

                continue

            # ------------------------------------------------
            # PIPELINE TIME
            # ------------------------------------------------

            pipeline_time = now() - pipeline_start

            # ------------------------------------------------
            # SAVE SOURCE EVENT MAPPING
            # ------------------------------------------------

            submitted_transaction_ids.append(
                transaction_id
            )

            submitted_payloads[
                transaction_id
            ] = payload.copy()

            source_timestamp_by_tx[
                transaction_id
            ] = source_timestamp_ms

            source_metadata_by_tx[
                transaction_id
            ] = {
                "image_index": image_index,
                "frame_id": frame_id,
                "image": image_path.name
            }

            # ------------------------------------------------
            # COMPONENT ARRAYS
            # ------------------------------------------------

            inference_times.append(
                inference_time
            )

            postprocess_times.append(
                post_time
            )

            json_times.append(
                json_time
            )

            pqc_times.append(
                pqc_time
            )

            mqtt_times.append(
                mqtt_time
            )

            pipeline_times.append(
                pipeline_time
            )

            processed_images += 1
            total_detections += detection_count

            # ------------------------------------------------
            # FRAME CSV
            # ------------------------------------------------

            csv_writer.writerow(
                {
                    "run_id":
                        run_id,

                    "status":
                        "submitted",

                    "failure_stage":
                        "",

                    "error_message":
                        "",

                    "transaction_id":
                        transaction_id,

                    "source_timestamp_ms":
                        source_timestamp_ms,

                    "source_timestamp_iso":
                        source_timestamp_iso,

                    "camera_id":
                        CAMERA_ID,

                    "dataset":
                        DATASET_NAME,

                    "sequence":
                        (
                            SEQUENCE_NAME
                            or ""
                        ),

                    "image_index":
                        image_index,

                    "frame_id":
                        (
                            frame_id
                            if frame_id is not None
                            else ""
                        ),

                    "image":
                        image_path.name,

                    "detection_count":
                        detection_count,

                    "yolo_inference_ms":
                        ms(inference_time),

                    "postprocessing_ms":
                        ms(post_time),

                    "json_generation_ms":
                        ms(json_time),

                    "pqc_signing_ms":
                        ms(pqc_time),

                    "mqtt_transmission_ms":
                        ms(mqtt_time),

                    "python_pipeline_ms":
                        ms(pipeline_time),

                    "model":
                        MODEL_PATH,

                    "image_size":
                        IMG_SIZE,

                    "confidence_threshold":
                        CONF_THRESHOLD,

                    "iou_threshold":
                        IOU_THRESHOLD,

                    "device":
                        device,

                    "fp16":
                        half
                }
            )

            csv_file.flush()

            print(
                f"🎯 Detections   : {detection_count}"
            )

            print(
                f"⏱️ YOLO         : "
                f"{ms(inference_time)} ms"
            )

            print(
                f"⏱️ Postprocess  : "
                f"{ms(post_time)} ms"
            )

            print(
                f"⏱️ JSON         : "
                f"{ms(json_time)} ms"
            )

            print(
                f"🔐 PQC sign     : "
                f"{ms(pqc_time)} ms"
            )

            print(
                f"📡 MQTT         : "
                f"{ms(mqtt_time)} ms"
            )

            print(
                f"⏱️ Python pipe  : "
                f"{ms(pipeline_time)} ms"
            )

            print(
                "📤 Status       : SUBMITTED"
            )

            # ------------------------------------------------
            # DISPLAY
            # ------------------------------------------------

            if not args.no_display:

                try:

                    annotated = result.plot()

                    cv2.putText(
                        annotated,
                        f"Run: {run_id}",
                        (20, 30),
                        cv2.FONT_HERSHEY_SIMPLEX,
                        0.7,
                        (0, 255, 0),
                        2
                    )

                    cv2.imshow(
                        f"YOLOChain D - {CAMERA_ID}",
                        annotated
                    )

                except Exception as error:

                    print(
                        "⚠️ Display error:",
                        error
                    )

            # ------------------------------------------------
            # TARGET FPS
            # ------------------------------------------------

            if TARGET_FPS > 0:

                elapsed = (
                    now()
                    -
                    pipeline_start
                )

                sleep_time = (
                    1.0 / TARGET_FPS
                    -
                    elapsed
                )

                if sleep_time > 0:
                    time.sleep(sleep_time)

            # ------------------------------------------------
            # ESC
            # ------------------------------------------------

            if not args.no_display:

                key = cv2.waitKey(1) & 0xFF

                if key == 27:

                    print(
                        "🛑 Stopped by user"
                    )

                    user_stopped = True
                    break

        # ====================================================
        # INITIAL PBFT DRAIN
        # ====================================================

        print()
        print("=" * 90)
        print(
            f"RUN {run_id}: INITIAL PBFT DRAIN"
        )
        print("=" * 90)

        (
            initial_committed_ids,
            initial_missing_ids,
            pbft_drain_time
        ) = wait_for_pbft_completion(
            submitted_transaction_ids,
            PBFT_METRICS_FILE,
            PBFT_TIMEOUT,
            PBFT_POLL_INTERVAL
        )

        initial_committed_ids = set(
            initial_committed_ids
        )

        initial_missing_ids = set(
            initial_missing_ids
        )

        # ====================================================
        # RECOVERY
        # ====================================================

        recovery_transaction_ids = []
        recovered_original_ids = set()
        recovery_history = []
        latest_tx_by_original = {}
        recovery_time_sec = 0.0

        if (
            initial_missing_ids
            and
            MAX_RECOVERY_RETRIES > 0
        ):

            recovery_result = (
                recover_missing_as_new_transactions(
                    initial_missing_ids,
                    submitted_payloads,
                    source_timestamp_by_tx,
                    MAX_RECOVERY_RETRIES,
                    RECOVERY_TIMEOUT,
                    PBFT_POLL_INTERVAL,
                    run_id
                )
            )

            recovery_transaction_ids = list(
                recovery_result[
                    "recovery_transaction_ids"
                ]
            )

            recovered_original_ids = set(
                recovery_result[
                    "recovered_original_ids"
                ]
            )

            recovery_history = list(
                recovery_result[
                    "recovery_history"
                ]
            )

            latest_tx_by_original = dict(
                recovery_result[
                    "latest_tx_by_original"
                ]
            )

            recovery_time_sec = float(
                recovery_result[
                    "recovery_time_sec"
                ]
            )

        # ====================================================
        # FINAL PBFT INDEX
        # ====================================================

        pbft_index = build_pbft_index(
            PBFT_METRICS_FILE
        )

        final_committed_metrics = set(
            pbft_index.keys()
        )

        # ====================================================
        # FINAL RECOVERY ACCOUNTING
        # ====================================================

        final_recovered_original_ids = set()

        for original_id in initial_missing_ids:

            recovery_tx_id = (
                latest_tx_by_original.get(
                    original_id
                )
            )

            if (
                recovery_tx_id
                and
                recovery_tx_id
                in final_committed_metrics
            ):

                final_recovered_original_ids.add(
                    original_id
                )

        recovered_original_ids = (
            final_recovered_original_ids
        )

        final_missing_ids = (
            initial_missing_ids
            -
            recovered_original_ids
        )

        # ====================================================
        # E2E CALCULATION
        # ====================================================

        e2e_values = []

        e2e_records = []

        # ----------------------------------------------------
        # ORIGINAL TRANSACTIONS
        # ----------------------------------------------------

        for original_tx_id in (
            submitted_transaction_ids
        ):

            pbft_row = pbft_index.get(
                original_tx_id
            )

            if pbft_row is not None:

                source_ts = (
                    source_timestamp_by_tx.get(
                        original_tx_id
                    )
                )

                record = extract_e2e_record(
                    tx_id=original_tx_id,
                    source_timestamp_ms=source_ts,
                    pbft_row=pbft_row,
                    run_id=run_id,
                    original_transaction_id=
                        original_tx_id
                )

                if record is not None:

                    e2e_records.append(record)
                    e2e_values.append(
                        record["e2e_latency_ms"]
                    )

        # ----------------------------------------------------
        # RECOVERED ORIGINAL EVENTS
        #
        # The recovery TX is committed, but the source
        # timestamp remains the timestamp of the ORIGINAL
        # source event.
        # ----------------------------------------------------

        for original_tx_id in (
            recovered_original_ids
        ):

            recovery_tx_id = (
                latest_tx_by_original.get(
                    original_tx_id
                )
            )

            if not recovery_tx_id:
                continue

            pbft_row = pbft_index.get(
                recovery_tx_id
            )

            if pbft_row is None:
                continue

            source_ts = (
                source_timestamp_by_tx.get(
                    original_tx_id
                )
            )

            record = extract_e2e_record(
                tx_id=recovery_tx_id,
                source_timestamp_ms=source_ts,
                pbft_row=pbft_row,
                run_id=run_id,
                original_transaction_id=
                    original_tx_id,
                recovery_transaction_id=
                    recovery_tx_id
            )

            if record is not None:

                e2e_records.append(record)
                e2e_values.append(
                    record["e2e_latency_ms"]
                )

        # ----------------------------------------------------
        # WRITE E2E RECORDS
        # ----------------------------------------------------

        for record in e2e_records:

            e2e_writer.writerow(record)

        e2e_file.flush()

        # ====================================================
        # E2E RUN STATISTICS
        # ====================================================

        e2e_summary = statistics_summary_ms(
            e2e_values
        )

        equivalent_fps = 0.0

        if e2e_summary["mean_ms"] > 0:

            equivalent_fps = (
                1000.0
                /
                e2e_summary["mean_ms"]
            )

        source_events = len(
            submitted_transaction_ids
        )

        canonical_committed_events = len(
            e2e_records
        )

        recovered_events = len(
            recovered_original_ids
        )

        missing_events = len(
            final_missing_ids
        )

        completion_rate = 0.0

        if source_events > 0:

            completion_rate = (
                canonical_committed_events
                /
                source_events
                *
                100.0
            )

        e2e_run_writer.writerow(
            {
                "run_id":
                    run_id,

                "source_events":
                    source_events,

                "canonical_committed_events":
                    canonical_committed_events,

                "recovered_events":
                    recovered_events,

                "missing_events":
                    missing_events,

                "e2e_mean_ms":
                    e2e_summary["mean_ms"],

                "e2e_median_ms":
                    e2e_summary["median_ms"],

                "e2e_std_ms":
                    e2e_summary["std_ms"],

                "e2e_p95_ms":
                    e2e_summary["p95_ms"],

                "e2e_p99_ms":
                    e2e_summary["p99_ms"],

                "e2e_min_ms":
                    e2e_summary["min_ms"],

                "e2e_max_ms":
                    e2e_summary["max_ms"],

                "equivalent_fps":
                    equivalent_fps,

                "completion_rate_percent":
                    completion_rate
            }
        )

        e2e_run_file.flush()

        # ====================================================
        # RUN TIME
        # ====================================================

        run_end = now()

        run_time = run_end - run_start

        python_fps = (
            processed_images / run_time
            if run_time > 0
            else 0.0
        )

        detection_rate = (
            total_detections / run_time
            if run_time > 0
            else 0.0
        )

        # ====================================================
        # RUN SUMMARY
        # ====================================================

        run_summary_writer.writerow(
            {
                "run_id":
                    run_id,

                "images_available":
                    len(image_files),

                "images_processed":
                    processed_images,

                "images_failed":
                    failed_images,

                "transactions_submitted":
                    len(
                        submitted_transaction_ids
                    ),

                "initial_committed":
                    len(
                        initial_committed_ids
                    ),

                "initial_missing":
                    len(
                        initial_missing_ids
                    ),

                "recovery_transactions":
                    len(
                        recovery_transaction_ids
                    ),

                "recovered_originals":
                    len(
                        recovered_original_ids
                    ),

                "final_missing_originals":
                    len(
                        final_missing_ids
                    ),

                "pbft_drain_sec":
                    round(
                        pbft_drain_time,
                        6
                    ),

                "recovery_time_sec":
                    round(
                        recovery_time_sec,
                        6
                    ),

                "experiment_time_sec":
                    round(
                        run_time,
                        6
                    ),

                "python_throughput_fps":
                    round(
                        python_fps,
                        6
                    ),

                "detection_rate_per_sec":
                    round(
                        detection_rate,
                        6
                    )
            }
        )

        run_summary_file.flush()

        # ====================================================
        # PBFT SUMMARY
        # ====================================================

        for original_id in submitted_transaction_ids:

            if original_id in initial_committed_ids:

                pbft_writer.writerow(
                    {
                        "run_id":
                            run_id,

                        "original_transaction_id":
                            original_id,

                        "initially_committed":
                            True,

                        "initially_missing":
                            False,

                        "recovery_attempt":
                            "",

                        "recovery_transaction_id":
                            "",

                        "recovery_published":
                            False,

                        "recovery_committed":
                            False,

                        "final_status":
                            "initial_commit"
                    }
                )

            else:

                records = [
                    r
                    for r in recovery_history
                    if r.get(
                        "original_transaction_id"
                    ) == original_id
                ]

                if records:

                    for record in records:

                        pbft_writer.writerow(
                            {
                                "run_id":
                                    run_id,

                                "original_transaction_id":
                                    original_id,

                                "initially_committed":
                                    False,

                                "initially_missing":
                                    True,

                                "recovery_attempt":
                                    record.get(
                                        "recovery_attempt",
                                        ""
                                    ),

                                "recovery_transaction_id":
                                    record.get(
                                        "recovery_transaction_id",
                                        ""
                                    ),

                                "recovery_published":
                                    record.get(
                                        "published",
                                        False
                                    ),

                                "recovery_committed":
                                    record.get(
                                        "committed",
                                        False
                                    ),

                                "final_status":
                                    (
                                        "recovered"
                                        if original_id
                                        in recovered_original_ids
                                        else
                                        "still_missing"
                                    )
                            }
                        )

                else:

                    pbft_writer.writerow(
                        {
                            "run_id":
                                run_id,

                            "original_transaction_id":
                                original_id,

                            "initially_committed":
                                False,

                            "initially_missing":
                                True,

                            "recovery_attempt":
                                "",

                            "recovery_transaction_id":
                                "",

                            "recovery_published":
                                False,

                            "recovery_committed":
                                False,

                            "final_status":
                                "still_missing"
                        }
                    )

        pbft_summary_file.flush()

        # ====================================================
        # COMPONENT STATISTICS
        # ====================================================

        components = [
            ("YOLO inference", inference_times),
            ("Post-processing", postprocess_times),
            ("JSON generation", json_times),
            ("PQC signing", pqc_times),
            ("MQTT publish/wait", mqtt_times),
            ("Python pipeline", pipeline_times)
        ]

        for component, values in components:

            summary = statistics_summary_ms(
                [
                    v * 1000.0
                    for v in values
                ]
            )

            summary_writer.writerow(
                {
                    "run_id":
                        run_id,

                    "component":
                        component,

                    "mean_ms":
                        summary["mean_ms"],

                    "median_ms":
                        summary["median_ms"],

                    "std_ms":
                        summary["std_ms"],

                    "p95_ms":
                        summary["p95_ms"],

                    "p99_ms":
                        summary["p99_ms"],

                    "min_ms":
                        summary["min_ms"],

                    "max_ms":
                        summary["max_ms"]
                }
            )

        summary_file.flush()

        # ====================================================
        # CONSOLE REPORT
        # ====================================================

        print()
        print("=" * 90)
        print(
            f"RUN {run_id} FINAL RESULTS"
        )
        print("=" * 90)

        print(
            "Images processed       :",
            processed_images
        )

        print(
            "Transactions submitted :",
            len(submitted_transaction_ids)
        )

        print(
            "Initial committed      :",
            len(initial_committed_ids)
        )

        print(
            "Initial missing        :",
            len(initial_missing_ids)
        )

        print(
            "Recovery transactions :",
            len(recovery_transaction_ids)
        )

        print(
            "Recovered originals    :",
            len(recovered_original_ids)
        )

        print(
            "Final missing          :",
            len(final_missing_ids)
        )

        print()
        print(
            "E2E source events      :",
            source_events
        )

        print(
            "E2E committed events  :",
            canonical_committed_events
        )

        print(
            "E2E mean              :",
            round(
                e2e_summary["mean_ms"],
                3
            ),
            "ms"
        )

        print(
            "E2E median            :",
            round(
                e2e_summary["median_ms"],
                3
            ),
            "ms"
        )

        print(
            "E2E SD                :",
            round(
                e2e_summary["std_ms"],
                3
            ),
            "ms"
        )

        print(
            "E2E P95               :",
            round(
                e2e_summary["p95_ms"],
                3
            ),
            "ms"
        )

        print(
            "E2E P99               :",
            round(
                e2e_summary["p99_ms"],
                3
            ),
            "ms"
        )

        print(
            "Equivalent FPS        :",
            round(
                equivalent_fps,
                3
            )
        )

        print(
            "Completion rate       :",
            round(
                completion_rate,
                3
            ),
            "%"
        )

        print(
            "Python processing FPS :",
            round(
                python_fps,
                3
            )
        )

        print("=" * 90)

        if not final_missing_ids:

            print(
                "✅ RUN STATUS: "
                "ALL SOURCE EVENTS COMMITTED "
                "OR RECOVERED"
            )

        else:

            print(
                "⚠️ RUN STATUS: "
                "SOME SOURCE EVENTS REMAIN MISSING"
            )

        # ====================================================
        # RUN METADATA
        # ====================================================

        all_run_metadata.append(
            {
                "run_id":
                    run_id,

                "images_available":
                    len(image_files),

                "images_processed":
                    processed_images,

                "images_failed":
                    failed_images,

                "transactions_submitted":
                    len(
                        submitted_transaction_ids
                    ),

                "initial_committed":
                    len(
                        initial_committed_ids
                    ),

                "initial_missing":
                    len(
                        initial_missing_ids
                    ),

                "recovery_transactions":
                    len(
                        recovery_transaction_ids
                    ),

                "recovered_originals":
                    len(
                        recovered_original_ids
                    ),

                "final_missing_originals":
                    len(
                        final_missing_ids
                    ),

                "e2e_mean_ms":
                    e2e_summary["mean_ms"],

                "e2e_median_ms":
                    e2e_summary["median_ms"],

                "e2e_std_ms":
                    e2e_summary["std_ms"],

                "e2e_p95_ms":
                    e2e_summary["p95_ms"],

                "e2e_p99_ms":
                    e2e_summary["p99_ms"],

                "equivalent_fps":
                    equivalent_fps,

                "completion_rate_percent":
                    completion_rate,

                "pbft_drain_time_sec":
                    round(
                        pbft_drain_time,
                        6
                    ),

                "recovery_time_sec":
                    round(
                        recovery_time_sec,
                        6
                    ),

                "experiment_time_sec":
                    round(
                        run_time,
                        6
                    ),

                "python_throughput_fps":
                    round(
                        python_fps,
                        6
                    ),

                "user_stopped":
                    user_stopped
            }
        )

        if user_stopped:
            break


finally:

    # ========================================================
    # CLOSE CSV FILES
    # ========================================================

    for file_obj in [
        csv_file,
        summary_file,
        run_summary_file,
        pbft_summary_file,
        e2e_file,
        e2e_run_file
    ]:

        try:
            file_obj.flush()
            file_obj.close()
        except Exception:
            pass

    # ========================================================
    # FAILED CSV
    # ========================================================

    try:

        with open(
            FAILED_CSV_PATH,
            "w",
            newline="",
            encoding="utf-8"
        ) as failed_file:

            failed_writer = csv.DictWriter(
                failed_file,
                fieldnames=[
                    "run_id",
                    "image_index",
                    "image",
                    "frame_id",
                    "transaction_id",
                    "stage",
                    "error",
                    "timestamp_ms"
                ]
            )

            failed_writer.writeheader()
            failed_writer.writerows(
                failed_records
            )

    except Exception as error:

        print(
            "⚠️ Could not write failed CSV:",
            error
        )

    # ========================================================
    # FINAL METADATA
    # ========================================================

    total_experiment_time = (
        now()
        -
        global_start
    )

    metadata = {

        "schema_version":
            "D.2-E2E",

        "experiment":
            "Experiment D",

        "description":
            "YOLOv8 + MQTT + PQC + PBFT-style Blockchain",

        "measurement_definition": {

            "e2e_latency":
                "canonical PBFT commit timestamp "
                "minus original camera/source timestamp",

            "e2e_is_direct_timestamp_difference":
                True,

            "e2e_is_component_sum":
                False,

            "mqtt_is_pure_propagation":
                False,

            "equivalent_fps":
                "1000 / mean E2E latency in ms",

            "equivalent_fps_is_sustained_throughput":
                False
        },

        "camera_id":
            CAMERA_ID,

        "dataset":
            DATASET_NAME,

        "sequence":
            SEQUENCE_NAME,

        "input_directory":
            str(
                IMAGE_FOLDER.resolve()
            ),

        "model":
            MODEL_PATH,

        "image_size":
            IMG_SIZE,

        "confidence_threshold":
            CONF_THRESHOLD,

        "iou_threshold":
            IOU_THRESHOLD,

        "warmup_iterations":
            10,

        "independent_runs_requested":
            RUNS,

        "device":
            device,

        "fp16":
            half,

        "python_version":
            platform.python_version(),

        "torch_version":
            torch.__version__,

        "opencv_version":
            cv2.__version__,

        "pqc_algorithm":
            PQC_ALGO_NAME,

        "pqc_algorithm_code":
            args.algo_code,

        "pqc_library":
            str(
                Path(
                    PQC_LIBRARY
                ).resolve()
            ),

        "mqtt_broker":
            MQTT_BROKER,

        "mqtt_port":
            MQTT_PORT,

        "mqtt_topic":
            MQTT_TOPIC,

        "mqtt_qos":
            1,

        "pbft_metrics_file":
            str(
                PBFT_METRICS_FILE
            ),

        "pbft_timeout_sec":
            PBFT_TIMEOUT,

        "pbft_poll_sec":
            PBFT_POLL_INTERVAL,

        "max_recovery_retries":
            MAX_RECOVERY_RETRIES,

        "recovery_timeout_sec":
            RECOVERY_TIMEOUT,

        "images_available":
            len(image_files),

        "total_experiment_time_sec":
            round(
                total_experiment_time,
                6
            ),

        "runs":
            all_run_metadata,

        "metrics_csv":
            str(CSV_PATH),

        "summary_csv":
            str(SUMMARY_CSV_PATH),

        "run_summary_csv":
            str(RUN_SUMMARY_PATH),

        "e2e_metrics_csv":
            str(E2E_METRICS_PATH),

        "e2e_run_summary_csv":
            str(E2E_RUN_SUMMARY_PATH),

        "failed_frames_csv":
            str(FAILED_CSV_PATH),

        "pbft_commit_summary_csv":
            str(PBFT_RESULT_PATH)
    }

    try:

        with open(
            METADATA_PATH,
            "w",
            encoding="utf-8"
        ) as metadata_file:

            json.dump(
                metadata,
                metadata_file,
                indent=2
            )

    except Exception as error:

        print(
            "⚠️ Could not write metadata:",
            error
        )

    # ========================================================
    # DISPLAY CLEANUP
    # ========================================================

    if not args.no_display:

        try:
            cv2.destroyAllWindows()
        except Exception:
            pass

    # ========================================================
    # MQTT CLEANUP
    # ========================================================

    try:
        client.loop_stop()
    except Exception:
        pass

    try:
        client.disconnect()
    except Exception:
        pass


# ============================================================
# FINAL INFORMATION
# ============================================================

print()
print("=" * 90)
print("EXPERIMENT D COMPLETED")
print("=" * 90)

print(
    "Requested independent runs :",
    RUNS
)

print(
    "Completed runs              :",
    len(all_run_metadata)
)

print(
    "Total experiment time       :",
    round(
        total_experiment_time,
        3
    ),
    "sec"
)

print()
print(
    "Per-frame metrics           :",
    CSV_PATH
)

print(
    "Component summary           :",
    SUMMARY_CSV_PATH
)

print(
    "Run summary                 :",
    RUN_SUMMARY_PATH
)

print(
    "E2E transaction metrics     :",
    E2E_METRICS_PATH
)

print(
    "E2E run summary             :",
    E2E_RUN_SUMMARY_PATH
)

print(
    "Failed frames               :",
    FAILED_CSV_PATH
)

print(
    "PBFT commit summary         :",
    PBFT_RESULT_PATH
)

print(
    "Experiment metadata         :",
    METADATA_PATH
)

print()
print(
    "Canonical PBFT metrics      :",
    PBFT_METRICS_FILE
)

print("=" * 90)

