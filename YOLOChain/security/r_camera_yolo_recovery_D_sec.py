#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
YOLOChain
Experiment D:
YOLOv8 + MQTT + PQC + PBFT-style Blockchain

NORMAL MODE
-----------
The normal Experiment D pipeline remains unchanged in structure:

    Camera
        |
        v
    YOLOv8
        |
        v
    PQC signature
        |
        v
    MQTT
        |
        v
    Validator 1 / Gateway
        |
        v
    PBFT-style P2P network
        |
        v
    Blockchain

SECURITY MODE
-------------
Security experiments:

    S1 = Replay attack
         1) exact replay of an accepted transaction
         2) NEW transaction ID with the SAME camera_id + sequence

    S2 = Modified signed metadata
         Modify the signed message AFTER signing while keeping
         the original PQC signature.

    S3 = Fake / unauthorized camera
         Modify camera_id inside the signed message and re-sign
         it using the legitimate signing key.

    S4 = MQTT outer-field tampering
         Modify an outer MQTT field without modifying the
         signed message or signature.

    S5 = Off-chain data tampering
         Compute SHA-256 of the media, then modify the local
         off-chain file and verify that the current hash differs
         from the authenticated/stored hash.

Security output:
    <results>/security/security_metrics.csv

Normal Experiment D output remains under:
    <results>/camera/<camera_id>/

Security mode deliberately avoids PBFT recovery because recovery
would create new transactions and would interfere with replay /
sequence-freshness measurements.
"""

import cv2
import time
import json
import base64
import ctypes
import torch
import uuid
import argparse
import csv
import statistics
import platform
import os
import hashlib
import copy

from pathlib import Path
from datetime import datetime, timezone

import paho.mqtt.client as mqtt
from ultralytics import YOLO


# ============================================================
# ARGUMENTS
# ============================================================

parser = argparse.ArgumentParser(
    description="YOLOChain Experiment D Camera + PQC + MQTT + PBFT"
)

parser.add_argument(
    "--dataset",
    choices=["coco128", "mot17"],
    required=True
)

parser.add_argument(
    "--input-dir",
    required=True
)

parser.add_argument(
    "--camera-id",
    default="camera_01"
)

parser.add_argument(
    "--sequence",
    default=None
)

parser.add_argument(
    "--model",
    default="yolov8n.pt"
)

parser.add_argument(
    "--img-size",
    type=int,
    default=416
)

parser.add_argument(
    "--conf",
    type=float,
    default=0.25
)

parser.add_argument(
    "--iou",
    type=float,
    default=0.50
)

parser.add_argument(
    "--target-fps",
    type=float,
    default=0
)

parser.add_argument(
    "--broker",
    default="localhost"
)

parser.add_argument(
    "--port",
    type=int,
    default=1883
)

parser.add_argument(
    "--topic",
    default="pqc/handshake"
)

parser.add_argument(
    "--algo-code",
    default="2"
)

parser.add_argument(
    "--algo-name",
    default="falcon-512"
)

parser.add_argument(
    "--pqc-library",
    default="./r1_sign_lib.so"
)

parser.add_argument(
    "--results-dir",
    default="results_D"
)

parser.add_argument(
    "--pbft-metrics-file",
    default="results_D/validator_1/results/pbft_metrics.csv"
)

parser.add_argument(
    "--pbft-timeout",
    type=float,
    default=20.0
)

parser.add_argument(
    "--pbft-poll",
    type=float,
    default=0.25
)

parser.add_argument(
    "--max-retries",
    type=int,
    default=100
)

parser.add_argument(
    "--recovery-timeout",
    type=float,
    default=10.0
)

parser.add_argument(
    "--max-images",
    type=int,
    default=0
)

parser.add_argument(
    "--runs",
    type=int,
    default=5
)

parser.add_argument(
    "--no-display",
    action="store_true"
)

# ============================================================
# SECURITY ARGUMENTS
# ============================================================

parser.add_argument(
    "--security-test",
    choices=[
        "NONE",
        "S1",
        "S2",
        "S3",
        "S4",
        "S5"
    ],
    default="NONE",
    help="Run one of S1-S5 security experiments"
)

parser.add_argument(
    "--attack-count",
    type=int,
    default=1,
    help="Number of attack attempts for S1"
)

parser.add_argument(
    "--attack-camera-id",
    default="fake_camera_999",
    help="Unauthorized camera ID used by S3"
)

parser.add_argument(
    "--security-results-dir",
    default=None,
    help="Security output directory. Default: <results-dir>/security"
)

parser.add_argument(
    "--security-topic",
    default="pqc/security/result",
    help="Optional security result MQTT topic"
)

args = parser.parse_args()


# ============================================================
# BASIC CONFIGURATION
# ============================================================

SECURITY_TEST = args.security_test.upper()

SECURITY_MODE = (
    SECURITY_TEST != "NONE"
)

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

PBFT_METRICS_FILE = Path(
    args.pbft_metrics_file
)

PBFT_TIMEOUT = args.pbft_timeout
PBFT_POLL_INTERVAL = args.pbft_poll

MAX_RECOVERY_RETRIES = args.max_retries
RECOVERY_TIMEOUT = args.recovery_timeout

RUNS = args.runs

if RUNS < 1:
    raise ValueError("--runs must be >= 1")

if args.attack_count < 1:
    raise ValueError("--attack-count must be >= 1")


# ============================================================
# RESULT DIRECTORIES
# ============================================================

RESULTS_ROOT = Path(
    args.results_dir
)

CAMERA_RESULTS_DIR = (
    RESULTS_ROOT /
    "camera" /
    CAMERA_ID
)

CAMERA_RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


if args.security_results_dir:
    SECURITY_RESULTS_DIR = Path(
        args.security_results_dir
    )
else:
    SECURITY_RESULTS_DIR = (
        RESULTS_ROOT /
        "security"
    )

SECURITY_RESULTS_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# NORMAL EXPERIMENT FILES
# ============================================================

CSV_PATH = (
    CAMERA_RESULTS_DIR /
    "camera_metrics.csv"
)

SUMMARY_CSV_PATH = (
    CAMERA_RESULTS_DIR /
    "camera_summary.csv"
)

METADATA_PATH = (
    CAMERA_RESULTS_DIR /
    "experiment_metadata.json"
)

FAILED_CSV_PATH = (
    CAMERA_RESULTS_DIR /
    "failed_frames.csv"
)

PBFT_RESULT_PATH = (
    CAMERA_RESULTS_DIR /
    "pbft_commit_summary.csv"
)

RUN_SUMMARY_PATH = (
    CAMERA_RESULTS_DIR /
    "run_summary.csv"
)


# ============================================================
# SECURITY FILE
# ============================================================

SECURITY_METRICS_PATH = (
    SECURITY_RESULTS_DIR /
    "security_metrics.csv"
)

SECURITY_PAYLOAD_DIR = (
    SECURITY_RESULTS_DIR /
    "payloads"
)

SECURITY_PAYLOAD_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# ============================================================
# SECURITY CSV
# ============================================================
# ============================================================
# SECURITY CSV — UNIFIED SCHEMA
# Must remain identical to the Node.js security CSV schema.
# ============================================================

# ============================================================
# SECURITY CSV — UNIFIED SCHEMA
# Must match the Node.js security CSV schema exactly.
# ============================================================

SECURITY_FIELDS = [

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
]

# ============================================================
# SECURITY CSV INITIALIZATION
# ============================================================

def initialize_security_csv():

    if (
        not SECURITY_METRICS_PATH.exists()
        or
        SECURITY_METRICS_PATH.stat().st_size == 0
    ):

        with open(
            SECURITY_METRICS_PATH,
            "w",
            newline="",
            encoding="utf-8"
        ) as security_file:

            writer = csv.DictWriter(
                security_file,
                fieldnames=SECURITY_FIELDS
            )

            writer.writeheader()


def write_security_metric(
    test_id,
    run_id,
    attack_type,
    transaction_id="",
    original_transaction_id="",
    camera_id="",
    sequence="",
    expected_result="",
    attack_action="",
    published="",
    signature_valid="",
    camera_authorized="",
    sequence_valid="",
    accepted="",
    detected="",
    rejection_reason="",
    offchain_hash_before="",
    offchain_hash_after="",
    offchain_hash_match="",
    attack_latency_ms="",
    actual_result="",
    duplicate_tx="",
    validator_id="1",
    node_id="camera_01",
    layer="CAMERA"
):

    initialize_security_csv()

    # --------------------------------------------------------
    # Normalize actual result
    # --------------------------------------------------------

    if not actual_result:

        if str(accepted).lower() in (
            "true",
            "1"
        ):
            actual_result = "accepted"

        elif str(accepted).lower() in (
            "false",
            "0"
        ):
            actual_result = "rejected"

        else:
            actual_result = ""

    # --------------------------------------------------------
    # Normalize duplicate transaction flag
    # --------------------------------------------------------

    if not duplicate_tx:

        if rejection_reason == "duplicate_tx_id":
            duplicate_tx = "true"

        else:
            duplicate_tx = "false"

    # --------------------------------------------------------
    # Detection latency
    # --------------------------------------------------------

    detection_latency_ms = attack_latency_ms

    # --------------------------------------------------------
    # Unified timestamp
    # --------------------------------------------------------

    timestamp = datetime.now(
        timezone.utc
    ).isoformat()

    row = {

        "test_id":
            test_id,

        "run_id":
            run_id,

        "attack_type":
            attack_type,

        "transaction_id":
            transaction_id,

        "camera_id":
            camera_id,

        "sequence":
            sequence,

        "expected_result":
            expected_result,

        "actual_result":
            actual_result,

        "accepted":
            accepted,

        "detected":
            detected,

        "rejection_reason":
            rejection_reason,

        "signature_valid":
            signature_valid,

        "camera_authorized":
            camera_authorized,

        "sequence_valid":
            sequence_valid,

        "duplicate_tx":
            duplicate_tx,

        "offchain_hash_match":
            offchain_hash_match,

        "detection_latency_ms":
            detection_latency_ms,

        "timestamp":
            timestamp,

        "validator_id":
            validator_id,

        "node_id":
            node_id,

        "layer":
            layer
    }

    with open(
        SECURITY_METRICS_PATH,
        "a",
        newline="",
        encoding="utf-8"
    ) as security_file:

        writer = csv.DictWriter(
            security_file,
            fieldnames=SECURITY_FIELDS,
            extrasaction="ignore"
        )

        writer.writerow(row)


# ============================================================
# TIMING HELPERS
# ============================================================

def now():
    return time.perf_counter()


def epoch_ms():
    return int(
        time.time() * 1000
    )


def ms(seconds):
    return round(
        seconds * 1000.0,
        3
    )


def percentile(values, p):

    if not values:
        return 0.0

    ordered = sorted(values)

    if len(ordered) == 1:
        return ordered[0] * 1000.0

    k = (
        (len(ordered) - 1)
        * (p / 100.0)
    )

    f = int(k)

    c = min(
        f + 1,
        len(ordered) - 1
    )

    if f == c:
        value = ordered[f]
    else:
        value = (
            ordered[f]
            + (
                ordered[c]
                - ordered[f]
            )
            * (k - f)
        )

    return value * 1000.0


def statistics_summary(values):

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

    values_ms = [
        x * 1000.0
        for x in values
    ]

    if len(values_ms) > 1:

        std_value = statistics.stdev(
            values_ms
        )

    else:

        std_value = 0.0

    return {

        "mean_ms":
            statistics.mean(values_ms),

        "median_ms":
            statistics.median(values_ms),

        "std_ms":
            std_value,

        "p95_ms":
            percentile(values, 95),

        "p99_ms":
            percentile(values, 99),

        "min_ms":
            min(values_ms),

        "max_ms":
            max(values_ms)
    }


# ============================================================
# SHA-256
# ============================================================

def sha256_file(
    file_path
):

    file_path = Path(
        file_path
    )

    digest = hashlib.sha256()

    with open(
        file_path,
        "rb"
    ) as file:

        while True:

            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(
                chunk
            )

    return digest.hexdigest()


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

    error_text = str(error)

    failed_records.append(
        {

            "run_id":
                run_id,

            "image_index":
                image_index,

            "image":
                (
                    image_path.name
                    if image_path is not None
                    else ""
                ),

            "frame_id":
                (
                    frame_id
                    if frame_id is not None
                    else ""
                ),

            "transaction_id":
                (
                    transaction_id
                    if transaction_id is not None
                    else ""
                ),

            "stage":
                stage,

            "error":
                error_text,

            "timestamp_ms":
                epoch_ms()
        }
    )

    print(
        f"❌ Run {run_id} | "
        f"Image {image_index} | "
        f"Stage={stage} | "
        f"Error={error_text}"
    )


# ============================================================
# PBFT CSV READER
# ============================================================

def read_committed_transaction_ids(
    metrics_file
):

    metrics_file = Path(
        metrics_file
    )

    if not metrics_file.exists():
        return set()

    committed = set()

    try:

        with open(
            metrics_file,
            "r",
            newline="",
            encoding="utf-8"
        ) as file:

            reader = csv.DictReader(
                file
            )

            for row in reader:

                tx_id = (
                    row.get("transaction_id")
                    or
                    row.get("tx_id")
                )

                if tx_id:

                    committed.add(
                        str(tx_id).strip()
                    )

    except Exception as error:

        print(
            "⚠️ Could not read PBFT metrics:",
            error
        )

    return committed


# ============================================================
# WAIT FOR PBFT
# ============================================================

def wait_for_pbft_completion(
    submitted_tx_ids,
    metrics_file,
    timeout_sec,
    poll_interval
):

    submitted = set(
        submitted_tx_ids
    )

    if not submitted:

        return (
            set(),
            set(),
            0.0
        )

    start = now()

    while True:

        committed = (
            read_committed_transaction_ids(
                metrics_file
            )
        )

        matched = (
            submitted &
            committed
        )

        missing = (
            submitted -
            committed
        )

        if not missing:

            elapsed = (
                now() - start
            )

            print(
                f"✅ PBFT completion: "
                f"{len(matched)}/"
                f"{len(submitted)}"
            )

            return (
                matched,
                missing,
                elapsed
            )

        elapsed = (
            now() - start
        )

        if elapsed >= timeout_sec:

            print(
                f"⚠️ PBFT timeout: "
                f"{len(matched)}/"
                f"{len(submitted)} "
                f"committed"
            )

            return (
                matched,
                missing,
                elapsed
            )

        time.sleep(
            poll_interval
        )


# ============================================================
# PQC SIGNING
# ============================================================

def sign_message_dict(
    message_obj
):

    message_bytes = json.dumps(
        message_obj,
        sort_keys=True,
        separators=(",", ":")
    ).encode(
        "utf-8"
    )

    sig_ptr = (
        ctypes.POINTER(
            ctypes.c_ubyte
        )()
    )

    pk_ptr = (
        ctypes.POINTER(
            ctypes.c_ubyte
        )()
    )

    sig_len = (
        ctypes.c_size_t()
    )

    pk_len = (
        ctypes.c_size_t()
    )

    ret = lib.pqc_sign(

        message_bytes,

        len(message_bytes),

        PQC_ALGO_CODE,

        ctypes.byref(
            sig_ptr
        ),

        ctypes.byref(
            sig_len
        ),

        ctypes.byref(
            pk_ptr
        ),

        ctypes.byref(
            pk_len
        )
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

                lib.pqc_free(
                    sig_ptr
                )

            except Exception:
                pass

        if bool(pk_ptr):

            try:

                lib.pqc_free(
                    pk_ptr
                )

            except Exception:
                pass

    return (
        message_bytes,
        signature,
        public_key
    )


# ============================================================
# BUILD MQTT PAYLOAD
# ============================================================

def build_mqtt_payload(
    message,
    signature,
    public_key
):

    transaction_id = (
        message["transaction_id"]
    )

    payload = {

        "transaction_id":
            transaction_id,

        "message_b64":
            base64.b64encode(
                json.dumps(
                    message,
                    sort_keys=True,
                    separators=(",", ":")
                ).encode("utf-8")
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
            message.get(
                "camera_id"
            ),

        "dataset":
            message.get(
                "dataset"
            ),

        "sequence":
            message.get(
                "sequence"
            ),

        "model":
            message.get(
                "model"
            ),

        "img_size":
            message.get(
                "img_size"
            ),

        "conf_threshold":
            message.get(
                "conf_threshold"
            ),

        "iou_threshold":
            message.get(
                "iou_threshold"
            ),

        "timestamp_ms":
            message.get(
                "timestamp_ms"
            ),

        "run_id":
            message.get(
                "run_id"
            ),

        "timing":
            message.get(
                "timing",
                {}
            )
    }

    return payload


# ============================================================
# MQTT PUBLISH
# ============================================================

def publish_payload(
    payload
):

    global mqtt_connected

    if not client.is_connected():

        try:

            client.reconnect()

        except Exception as error:

            print(
                "⚠️ MQTT reconnect failed:",
                error
            )

        deadline = (
            time.time() + 5
        )

        while (
            not client.is_connected()
            and
            time.time() < deadline
        ):

            time.sleep(
                0.05
            )

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
        info.rc
        ==
        mqtt.MQTT_ERR_SUCCESS
    )


# ============================================================
# SECURITY PAYLOAD SAVE
# ============================================================

def save_security_payload(
    test_id,
    payload,
    suffix=""
):

    tx_id = (
        payload.get(
            "transaction_id",
            uuid.uuid4().hex
        )
    )

    filename = (
        f"{test_id}_"
        f"{tx_id}"
        f"{suffix}.json"
    )

    path = (
        SECURITY_PAYLOAD_DIR /
        filename
    )

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            payload,
            file,
            indent=2
        )

    return path


# ============================================================
# SECURITY BASE MESSAGE
# ============================================================

def create_security_message(
    image_path,
    run_id=1
):

    frame = cv2.imread(
        str(image_path)
    )

    if frame is None:

        raise RuntimeError(
            f"Unable to read image: {image_path}"
        )

    transaction_id = (
        uuid.uuid4().hex
    )

    source_timestamp_ms = (
        epoch_ms()
    )

    source_timestamp_iso = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )

    # --------------------------------------------------------
    # YOLO
    # --------------------------------------------------------

    synchronize_cuda()

    inference_start = now()

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

    inference_time = (
        now() -
        inference_start
    )

    # --------------------------------------------------------
    # DETECTIONS
    # --------------------------------------------------------

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

                "class_id":
                    cls_id,

                "class":
                    result.names[
                        cls_id
                    ],

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

    # --------------------------------------------------------
    # FRAME ID
    # --------------------------------------------------------

    if args.dataset == "mot17":

        try:

            frame_id = int(
                image_path.stem
            )

        except ValueError:

            frame_id = 1

    else:

        frame_id = None

    # --------------------------------------------------------
    # S5 HASH
    # --------------------------------------------------------

    media_hash = sha256_file(
        image_path
    )

    # --------------------------------------------------------
    # MESSAGE
    # --------------------------------------------------------

    message = {

        "schema_version":
            "1.2",

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
            1,

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

        "media_sha256":
            media_hash,

        "offchain_file":
            str(
                image_path.resolve()
            ),

        "timing":
            {

                "yolo_inference_ms":
                    ms(
                        inference_time
                    )
            }
    }

    return message


# ============================================================
# SECURITY: CREATE SIGNED PAYLOAD
# ============================================================

def create_signed_security_payload(
    message
):

    (
        message_bytes,
        signature,
        public_key
    ) = sign_message_dict(
        message
    )

    payload = {

        "transaction_id":
            message[
                "transaction_id"
            ],

        "message_b64":
            base64.b64encode(
                message_bytes
            ).decode(
                "utf-8"
            ),

        "signature_b64":
            base64.b64encode(
                signature
            ).decode(
                "utf-8"
            ),

        "public_key_b64":
            base64.b64encode(
                public_key
            ).decode(
                "utf-8"
            ),

        "algo":
            PQC_ALGO_NAME,

        "algo_name":
            PQC_ALGO_NAME,

        "algo_code":
            args.algo_code,

        "camera_id":
            message.get(
                "camera_id"
            ),

        "dataset":
            message.get(
                "dataset"
            ),

        "sequence":
            message.get(
                "sequence"
            ),

        "model":
            message.get(
                "model"
            ),

        "img_size":
            message.get(
                "img_size"
            ),

        "conf_threshold":
            message.get(
                "conf_threshold"
            ),

        "iou_threshold":
            message.get(
                "iou_threshold"
            ),

        "timestamp_ms":
            message.get(
                "timestamp_ms"
            ),

        "run_id":
            message.get(
                "run_id"
            ),

        "timing":
            message.get(
                "timing",
                {}
            )
    }

    return (
        payload,
        message_bytes,
        signature,
        public_key
    )


# ============================================================
# SECURITY: WAIT
# ============================================================

def security_wait(
    seconds=2.0
):

    deadline = (
        time.time()
        +
        seconds
    )

    while (
        time.time()
        <
        deadline
    ):

        time.sleep(
            0.05
        )


# ============================================================
# S1 — REPLAY ATTACK
# ============================================================

def security_S1(
    base_payload,
    run_id
):

    print()
    print("=" * 90)
    print("S1 — REPLAY ATTACK")
    print("=" * 90)

    original_tx_id = (
        base_payload[
            "transaction_id"
        ]
    )

    # --------------------------------------------------------
    # First legitimate submission
    # --------------------------------------------------------

    print(
        "\n[ S1-BASELINE ] "
        "Publishing legitimate transaction..."
    )

    baseline_start = now()

    baseline_published = (
        publish_payload(
            base_payload
        )
    )

    baseline_latency = (
        now() -
        baseline_start
    )

    save_security_payload(
        "S1_BASELINE",
        base_payload
    )

    write_security_metric(

        test_id="S1-BASELINE",

        run_id=run_id,

        attack_type="BASELINE",

        transaction_id=
            original_tx_id,

        original_transaction_id=
            original_tx_id,

        camera_id=
            base_payload.get(
                "camera_id",
                ""
            ),

        sequence=
            base_payload.get(
                "sequence",
                ""
            ),

        expected_result=
            "ACCEPT",

        attack_action=
            "legitimate baseline",

        published=
            baseline_published,

        attack_latency_ms=
            ms(
                baseline_latency
            )
    )

    security_wait(2.0)

    # --------------------------------------------------------
    # S1-A EXACT REPLAY
    # --------------------------------------------------------

    print()
    print(
        "[ S1-A ] Exact replay"
    )

    for attempt in range(
        1,
        args.attack_count + 1
    ):

        attack_start = now()

        published = (
            publish_payload(
                copy.deepcopy(
                    base_payload
                )
            )
        )

        attack_latency = (
            now() -
            attack_start
        )

        test_id = (
            f"S1-A-{attempt}"
        )

        save_security_payload(
            test_id,
            base_payload
        )

        print(
            f"📤 {test_id} | "
            f"same transaction_id="
            f"{original_tx_id}"
        )

        write_security_metric(

            test_id=test_id,

            run_id=run_id,

            attack_type=
                "S1_REPLAY_EXACT",

            transaction_id=
                original_tx_id,

            original_transaction_id=
                original_tx_id,

            camera_id=
                base_payload.get(
                    "camera_id",
                    ""
                ),

            sequence=
                base_payload.get(
                    "sequence",
                    ""
                ),

            expected_result=
                "REJECT",

            attack_action=
                "exact replay of previously submitted transaction",

            published=
                published,

            attack_latency_ms=
                ms(
                    attack_latency
                )
        )

        security_wait(0.5)

    # --------------------------------------------------------
    # S1-B NEW TX ID, SAME SEQUENCE
    # --------------------------------------------------------

    print()
    print(
        "[ S1-B ] New transaction ID "
        "with SAME camera_id + sequence"
    )

    for attempt in range(
        1,
        args.attack_count + 1
    ):

        message_bytes = (
            base64.b64decode(
                base_payload[
                    "message_b64"
                ]
            )
        )

        message = json.loads(
            message_bytes.decode(
                "utf-8"
            )
        )

        new_tx_id = (
            uuid.uuid4().hex
        )

        message[
            "transaction_id"
        ] = new_tx_id

        # IMPORTANT:
        # The sequence is deliberately NOT changed.

        (
            new_payload,
            _,
            _,
            _
        ) = create_signed_security_payload(
            message
        )

        attack_start = now()

        published = (
            publish_payload(
                new_payload
            )
        )

        attack_latency = (
            now() -
            attack_start
        )

        test_id = (
            f"S1-B-{attempt}"
        )

        save_security_payload(
            test_id,
            new_payload
        )

        print(
            f"📤 {test_id} | "
            f"new_tx={new_tx_id} | "
            f"same_sequence="
            f"{message.get('sequence')}"
        )

        write_security_metric(

            test_id=test_id,

            run_id=run_id,

            attack_type=
                "S1_REPLAY_NEW_TX_SAME_SEQUENCE",

            transaction_id=
                new_tx_id,

            original_transaction_id=
                original_tx_id,

            camera_id=
                message.get(
                    "camera_id",
                    ""
                ),

            sequence=
                message.get(
                    "sequence",
                    ""
                ),

            expected_result=
                "REJECT",

            attack_action=
                "new transaction ID with previously used camera_id + sequence",

            published=
                published,

            signature_valid=
                True,

            attack_latency_ms=
                ms(
                    attack_latency
                )
        )

        security_wait(0.5)

    print()
    print(
        "S1 attack traffic completed."
    )


# ============================================================
# S2 — MODIFIED SIGNED MESSAGE
# ============================================================

def security_S2(
    base_payload,
    run_id
):

    print()
    print("=" * 90)
    print("S2 — MODIFIED SIGNED METADATA")
    print("=" * 90)

    original_tx_id = (
        base_payload[
            "transaction_id"
        ]
    )

    original_message_bytes = (
        base64.b64decode(
            base_payload[
                "message_b64"
            ]
        )
    )

    original_message = json.loads(
        original_message_bytes.decode(
            "utf-8"
        )
    )

    attack_message = (
        copy.deepcopy(
            original_message
        )
    )

    # --------------------------------------------------------
    # Modify authenticated metadata.
    # Keep the ORIGINAL signature.
    # --------------------------------------------------------

    attack_message[
        "detection_count"
    ] = (
        int(
            attack_message.get(
                "detection_count",
                0
            )
        )
        +
        1
    )

    attack_message[
        "camera_id"
    ] = (
        "camera_tampered"
    )

    modified_bytes = json.dumps(
        attack_message,
        sort_keys=True,
        separators=(",", ":")
    ).encode(
        "utf-8"
    )

    attack_payload = (
        copy.deepcopy(
            base_payload
        )
    )

    attack_payload[
        "message_b64"
    ] = base64.b64encode(
        modified_bytes
    ).decode(
        "utf-8"
    )

    # Signature deliberately remains original.

    attack_payload[
        "transaction_id"
    ] = original_tx_id

    test_id = "S2-1"

    save_security_payload(
        test_id,
        attack_payload
    )

    print(
        "Original transaction:",
        original_tx_id
    )

    print(
        "Modified fields: "
        "camera_id + detection_count"
    )

    attack_start = now()

    published = publish_payload(
        attack_payload
    )

    attack_latency = (
        now() -
        attack_start
    )

    write_security_metric(

        test_id=test_id,

        run_id=run_id,

        attack_type=
            "S2_MODIFIED_SIGNED_METADATA",

        transaction_id=
            original_tx_id,

        original_transaction_id=
            original_tx_id,

        camera_id=
            attack_message.get(
                "camera_id",
                ""
            ),

        sequence=
            attack_message.get(
                "sequence",
                ""
            ),

        expected_result=
            "REJECT",

        attack_action=
            "modified signed message while retaining original PQC signature",

        published=
            published,

        signature_valid=
            False,

        attack_latency_ms=
            ms(
                attack_latency
            )
    )

    print(
        "📤 S2 payload published."
    )

    print(
        "Expected: PQC signature verification failure."
    )


# ============================================================
# S3 — FAKE / UNAUTHORIZED CAMERA
# ============================================================

def security_S3(
    base_payload,
    run_id
):

    print()
    print("=" * 90)
    print("S3 — FAKE / UNAUTHORIZED CAMERA")
    print("=" * 90)

    original_message_bytes = (
        base64.b64decode(
            base_payload[
                "message_b64"
            ]
        )
    )

    original_message = json.loads(
        original_message_bytes.decode(
            "utf-8"
        )
    )

    fake_message = (
        copy.deepcopy(
            original_message
        )
    )

    fake_camera = (
        args.attack_camera_id
    )

    fake_message[
        "camera_id"
    ] = fake_camera

    fake_message[
        "transaction_id"
    ] = uuid.uuid4().hex

    (
        fake_payload,
        _,
        _,
        _
    ) = create_signed_security_payload(
        fake_message
    )

    test_id = "S3-1"

    save_security_payload(
        test_id,
        fake_payload
    )

    attack_start = now()

    published = publish_payload(
        fake_payload
    )

    attack_latency = (
        now() -
        attack_start
    )

    print(
        f"📤 Unauthorized camera: "
        f"{fake_camera}"
    )

    print(
        "Signature: valid because the "
        "message was re-signed."
    )

    print(
        "Expected: camera authorization rejection."
    )

    write_security_metric(

        test_id=test_id,

        run_id=run_id,

        attack_type=
            "S3_FAKE_UNAUTHORIZED_CAMERA",

        transaction_id=
            fake_message[
                "transaction_id"
            ],

        original_transaction_id=
            original_message[
                "transaction_id"
            ],

        camera_id=
            fake_camera,

        sequence=
            fake_message.get(
                "sequence",
                ""
            ),

        expected_result=
            "REJECT",

        attack_action=
            "valid PQC signature but unauthorized camera_id",

        published=
            published,

        signature_valid=
            True,

        camera_authorized=
            False,

        attack_latency_ms=
            ms(
                attack_latency
            )
    )


# ============================================================
# S4 — MQTT OUTER-FIELD TAMPERING
# ============================================================

def security_S4(
    base_payload,
    run_id
):

    print()
    print("=" * 90)
    print("S4 — MQTT OUTER-FIELD TAMPERING")
    print("=" * 90)

    attack_payload = (
        copy.deepcopy(
            base_payload
        )
    )

    original_camera = (
        attack_payload.get(
            "camera_id",
            ""
        )
    )

    attack_payload[
        "camera_id"
    ] = (
        "camera_MITM"
    )

    test_id = "S4-1"

    save_security_payload(
        test_id,
        attack_payload
    )

    print(
        "Signed camera_id:",
        original_camera
    )

    print(
        "Outer MQTT camera_id:",
        attack_payload[
            "camera_id"
        ]
    )

    attack_start = now()

    published = publish_payload(
        attack_payload
    )

    attack_latency = (
        now() -
        attack_start
    )

    write_security_metric(

        test_id=test_id,

        run_id=run_id,

        attack_type=
            "S4_MQTT_OUTER_FIELD_TAMPERING",

        transaction_id=
            attack_payload[
                "transaction_id"
            ],

        original_transaction_id=
            attack_payload[
                "transaction_id"
            ],

        camera_id=
            attack_payload[
                "camera_id"
            ],

        sequence=
            attack_payload.get(
                "sequence",
                ""
            ),

        expected_result=
            "REJECT",

        attack_action=
            "modified outer MQTT camera_id without changing signed message",

        published=
            published,

        signature_valid=
            True,

        attack_latency_ms=
            ms(
                attack_latency
            )
    )

    print(
        "Expected: outer/signed metadata mismatch."
    )


# ============================================================
# S5 — OFF-CHAIN DATA TAMPERING
# ============================================================

def security_S5(
    base_message,
    run_id,
    image_path
):

    print()
    print("=" * 90)
    print("S5 — OFF-CHAIN DATA TAMPERING")
    print("=" * 90)

    if not image_path.exists():

        raise FileNotFoundError(
            f"Image not found: {image_path}"
        )

    original_hash = (
        sha256_file(
            image_path
        )
    )

    print(
        "Original file:",
        image_path
    )

    print(
        "Original SHA-256:",
        original_hash
    )

    # --------------------------------------------------------
    # Copy file to security workspace.
    # We NEVER modify the original dataset.
    # --------------------------------------------------------

    tampered_file = (
        SECURITY_RESULTS_DIR /
        f"S5_offchain_{image_path.name}"
    )

    original_bytes = (
        image_path.read_bytes()
    )

    tampered_file.write_bytes(
        original_bytes
    )

    # --------------------------------------------------------
    # Modify one byte in the copied off-chain file.
    # --------------------------------------------------------

    tampered_bytes = bytearray(
        tampered_file.read_bytes()
    )

    if not tampered_bytes:

        raise RuntimeError(
            "Off-chain file is empty."
        )

    tampered_bytes[
        len(tampered_bytes) // 2
    ] ^= 0x01

    tampered_file.write_bytes(
        bytes(
            tampered_bytes
        )
    )

    tampered_hash = (
        sha256_file(
            tampered_file
        )
    )

    hash_match = (
        original_hash ==
        tampered_hash
    )

    print(
        "Tampered file:",
        tampered_file
    )

    print(
        "Tampered SHA-256:",
        tampered_hash
    )

    print(
        "Hash match:",
        hash_match
    )

    # --------------------------------------------------------
    # Build authenticated metadata.
    # The signed hash remains the ORIGINAL hash.
    # --------------------------------------------------------

    s5_message = (
        copy.deepcopy(
            base_message
        )
    )

    s5_message[
        "transaction_id"
    ] = uuid.uuid4().hex

    s5_message[
        "media_sha256"
    ] = original_hash

    s5_message[
        "offchain_file"
    ] = str(
        tampered_file.resolve()
    )

    (
        s5_payload,
        _,
        _,
        _
    ) = create_signed_security_payload(
        s5_message
    )

    test_id = "S5-1"

    save_security_payload(
        test_id,
        s5_payload
    )

    write_security_metric(

        test_id=test_id,

        run_id=run_id,

        attack_type=
            "S5_OFFCHAIN_DATA_TAMPERING",

        transaction_id=
            s5_message[
                "transaction_id"
            ],

        original_transaction_id=
            base_message[
                "transaction_id"
            ],

        camera_id=
            s5_message.get(
                "camera_id",
                ""
            ),

        sequence=
            s5_message.get(
                "sequence",
                ""
            ),

        expected_result=
            "DETECT",

        attack_action=
            "modified copied off-chain media after authenticated hash was recorded",

        published=
            False,

        signature_valid=
            True,

        offchain_hash_before=
            original_hash,

        offchain_hash_after=
            tampered_hash,

        offchain_hash_match=
            hash_match,

        detected=
            not hash_match,

        rejection_reason=
            (
                "SHA256_MISMATCH"
                if not hash_match
                else
                "UNEXPECTED_HASH_MATCH"
            )
    )

    print()
    print(
        "S5 result:"
    )

    if not hash_match:

        print(
            "✅ OFF-CHAIN TAMPERING DETECTED"
        )

    else:

        print(
            "❌ OFF-CHAIN TAMPERING WAS NOT DETECTED"
        )

    print(
        "Security metric written to:",
        SECURITY_METRICS_PATH
    )


# ============================================================
# SECURITY BASELINE
# ============================================================

def create_security_baseline():

    print()
    print(
        "Creating legitimate security baseline..."
    )

    baseline_image = (
        image_files[0]
    )

    message = (
        create_security_message(
            baseline_image,
            run_id=1
        )
    )

    (
        payload,
        _,
        _,
        _
    ) = create_signed_security_payload(
        message
    )

    save_security_payload(
        "BASELINE",
        payload
    )

    return (
        message,
        payload,
        baseline_image
    )


# ============================================================
# RUN SECURITY EXPERIMENT
# ============================================================

def run_security_experiment():

    print()
    print("=" * 90)
    print(
        f"YOLOCHAIN SECURITY EXPERIMENT {SECURITY_TEST}"
    )
    print("=" * 90)

    print(
        "Security results:",
        SECURITY_RESULTS_DIR
    )

    print(
        "Security metrics:",
        SECURITY_METRICS_PATH
    )

    (
        baseline_message,
        baseline_payload,
        baseline_image
    ) = create_security_baseline()

    print(
        "Baseline transaction:",
        baseline_message[
            "transaction_id"
        ]
    )

    # --------------------------------------------------------
    # First submit a legitimate baseline for replay tests.
    # For S5 the baseline is not required to be accepted by
    # blockchain; the authenticated hash is what matters.
    # --------------------------------------------------------

    if SECURITY_TEST in (
        "S1",
        "S2",
        "S3",
        "S4"
    ):

        print()
        print(
            "Publishing legitimate baseline..."
        )

        baseline_start = now()

        baseline_published = (
            publish_payload(
                baseline_payload
            )
        )

        baseline_latency = (
            now()
            -
            baseline_start
        )

        write_security_metric(

            test_id="BASELINE",

            run_id=1,

            attack_type="SECURITY_BASELINE",

            transaction_id=
                baseline_message[
                    "transaction_id"
                ],

            original_transaction_id=
                baseline_message[
                    "transaction_id"
                ],

            camera_id=
                baseline_message.get(
                    "camera_id",
                    ""
                ),

            sequence=
                baseline_message.get(
                    "sequence",
                    ""
                ),

            expected_result=
                "ACCEPT",

            attack_action=
                "legitimate security baseline",

            published=
                baseline_published,

            signature_valid=
                True,

            camera_authorized=
                True,

            sequence_valid=
                True,

            accepted=
                "",

            detected=
                "",

            attack_latency_ms=
                ms(
                    baseline_latency
                )
        )

        security_wait(
            3.0
        )

    # --------------------------------------------------------
    # Dispatch
    # --------------------------------------------------------

    if SECURITY_TEST == "S1":

        security_S1(
            baseline_payload,
            1
        )

    elif SECURITY_TEST == "S2":

        security_S2(
            baseline_payload,
            1
        )

    elif SECURITY_TEST == "S3":

        security_S3(
            baseline_payload,
            1
        )

    elif SECURITY_TEST == "S4":

        security_S4(
            baseline_payload,
            1
        )

    elif SECURITY_TEST == "S5":

        security_S5(
            baseline_message,
            1,
            baseline_image
        )

    print()
    print("=" * 90)
    print(
        f"{SECURITY_TEST} COMPLETED"
    )
    print("=" * 90)

    print(
        "Security metrics:",
        SECURITY_METRICS_PATH
    )


# ============================================================
# NORMAL EXPERIMENT D
# ============================================================

def run_normal_experiment():

    print()
    print("=" * 90)

    print(
        "YOLOCHAIN EXPERIMENT D"
    )

    print(
        "UNIFIED CAMERA + PQC + MQTT + PBFT"
    )

    print("=" * 90)

    print(
        "Camera ID        :",
        CAMERA_ID
    )

    print(
        "Dataset          :",
        DATASET_NAME
    )

    print(
        "Sequence         :",
        SEQUENCE_NAME
    )

    print(
        "Input directory  :",
        IMAGE_FOLDER
    )

    print(
        "Model            :",
        MODEL_PATH
    )

    print(
        "Image size       :",
        IMG_SIZE
    )

    print(
        "Confidence       :",
        CONF_THRESHOLD
    )

    print(
        "IoU threshold    :",
        IOU_THRESHOLD
    )

    print(
        "Warm-ups         :",
        10
    )

    print(
        "Independent runs :",
        RUNS
    )

    print(
        "PQC algorithm    :",
        PQC_ALGO_NAME
    )

    print(
        "PQC code         :",
        args.algo_code
    )

    print(
        "PQC library      :",
        PQC_LIBRARY
    )

    print(
        "MQTT broker      :",
        MQTT_BROKER
    )

    print(
        "MQTT port        :",
        MQTT_PORT
    )

    print(
        "MQTT topic       :",
        MQTT_TOPIC
    )

    print(
        "PBFT metrics     :",
        PBFT_METRICS_FILE
    )

    print(
        "PBFT timeout     :",
        PBFT_TIMEOUT,
        "sec"
    )

    print(
        "Max recovery     :",
        MAX_RECOVERY_RETRIES,
        "round(s)"
    )

    print(
        "Recovery timeout :",
        RECOVERY_TIMEOUT,
        "sec/round"
    )

    print(
        "Results directory:",
        RESULTS_ROOT
    )

    print(
        "Target FPS       :",
        (
            TARGET_FPS
            if TARGET_FPS > 0
            else "Maximum speed"
        )
    )

    print(
        "Display           :",
        (
            "Disabled"
            if args.no_display
            else "Enabled"
        )
    )

    print("=" * 90)

    # ========================================================
    # VALIDATE INPUT
    # ========================================================

    if not IMAGE_FOLDER.exists():

        raise FileNotFoundError(
            "Image folder does not exist:\n"
            f"{IMAGE_FOLDER}"
        )

    if not IMAGE_FOLDER.is_dir():

        raise NotADirectoryError(
            "Input path is not a directory:\n"
            f"{IMAGE_FOLDER}"
        )

    # ========================================================
    # LOAD IMAGE LIST
    # ========================================================

    image_files = sorted(
        [
            path
            for path in IMAGE_FOLDER.iterdir()
            if (
                path.is_file()
                and
                path.suffix.lower()
                in IMAGE_EXTENSIONS
            )
        ]
    )

    if not image_files:

        raise RuntimeError(
            "No supported images were found in:\n"
            f"{IMAGE_FOLDER}"
        )

    if args.max_images > 0:

        image_files = image_files[
            :args.max_images
        ]

    print()
    print(
        f"Found {len(image_files)} images/frames"
    )

    # ========================================================
    # DEVICE
    # ========================================================

    device = (
        "cuda"
        if torch.cuda.is_available()
        else "cpu"
    )

    half = (
        device == "cuda"
    )

    print(
        "Device           :",
        device
    )

    print(
        "FP16             :",
        half
    )

    # ========================================================
    # CUDA
    # ========================================================

    def synchronize_cuda():

        if (
            device == "cuda"
            and
            torch.cuda.is_available()
        ):

            torch.cuda.synchronize()

    # ========================================================
    # MQTT
    # ========================================================

    MQTT_CLIENT_ID = (
        f"yolo-{CAMERA_ID}-"
        f"{uuid.uuid4().hex[:8]}"
    )

    mqtt_connected = False

    def on_connect(
        client_obj,
        userdata,
        flags,
        rc
    ):

        nonlocal mqtt_connected

        if rc == 0:

            mqtt_connected = True

            print(
                f"🟢 MQTT connected | "
                f"Client ID: {MQTT_CLIENT_ID}"
            )

        else:

            mqtt_connected = False

            print(
                f"❌ MQTT connection failed | "
                f"rc={rc}"
            )

    def on_disconnect(
        client_obj,
        userdata,
        rc
    ):

        nonlocal mqtt_connected

        mqtt_connected = False

        print(
            f"⚠️ MQTT disconnected | "
            f"rc={rc}"
        )

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
    print(
        "Connecting to MQTT..."
    )

    client.connect(
        MQTT_BROKER,
        MQTT_PORT,
        keepalive=60
    )

    client.loop_start()

    connect_deadline = (
        time.time() + 10
    )

    while (
        not mqtt_connected
        and
        time.time()
        <
        connect_deadline
    ):

        time.sleep(0.05)

    if not mqtt_connected:

        client.loop_stop()

        raise RuntimeError(
            "Unable to connect to MQTT broker"
        )

    # ========================================================
    # PQC LIBRARY
    # ========================================================

    print()
    print(
        "Loading PQC library..."
    )

    if not Path(
        PQC_LIBRARY
    ).exists():

        client.loop_stop()

        raise FileNotFoundError(
            "PQC shared library not found:\n"
            f"{PQC_LIBRARY}"
        )

    lib = ctypes.CDLL(
        PQC_LIBRARY
    )

    # ========================================================
    # PQC ABI
    # ========================================================

    lib.pqc_sign.argtypes = [

        ctypes.c_char_p,

        ctypes.c_size_t,

        ctypes.c_char,

        ctypes.POINTER(
            ctypes.POINTER(
                ctypes.c_ubyte
            )
        ),

        ctypes.POINTER(
            ctypes.c_size_t
        ),

        ctypes.POINTER(
            ctypes.POINTER(
                ctypes.c_ubyte
            )
        ),

        ctypes.POINTER(
            ctypes.c_size_t
        )
    ]

    lib.pqc_sign.restype = (
        ctypes.c_int
    )

    lib.pqc_free.argtypes = [

        ctypes.POINTER(
            ctypes.c_ubyte
        )
    ]

    lib.pqc_free.restype = None

    print(
        "✅ PQC library loaded"
    )

    # ========================================================
    # LOAD YOLO
    # ========================================================

    print()
    print(
        "🔥 Loading YOLO model..."
    )

    model_load_start = now()

    model = YOLO(
        MODEL_PATH
    )

    model.to(
        device
    )

    synchronize_cuda()

    model_load_end = now()

    model_load_time = (
        model_load_end
        -
        model_load_start
    )

    print(
        "✅ YOLO model loaded in",
        ms(model_load_time),
        "ms"
    )

    # ========================================================
    # WARMUP
    # ========================================================

    warmup_image = cv2.imread(
        str(image_files[0])
    )

    if warmup_image is not None:

        print()
        print(
            "🔥 YOLO warm-up: 10 iterations..."
        )

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

        print(
            "✅ Warm-up completed"
        )

    # ========================================================
    # NORMAL CSV FILES
    # ========================================================

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

    # ========================================================
    # SUMMARY
    # ========================================================

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

    # ========================================================
    # RUN SUMMARY
    # ========================================================

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

    # ========================================================
    # PBFT SUMMARY
    # ========================================================

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

    all_run_metadata = []

    global_start = now()

    # ========================================================
    # RECOVERY FUNCTIONS
    # ========================================================

    def create_recovery_payload(
        original_payload,
        original_transaction_id,
        attempt,
        run_id
    ):

        original_message_bytes = (
            base64.b64decode(
                original_payload[
                    "message_b64"
                ]
            )
        )

        original_message = json.loads(
            original_message_bytes.decode(
                "utf-8"
            )
        )

        recovery_transaction_id = (
            uuid.uuid4().hex
        )

        recovery_message = (
            dict(original_message)
        )

        recovery_message[
            "transaction_id"
        ] = recovery_transaction_id

        recovery_message[
            "recovery_of"
        ] = original_transaction_id

        recovery_message[
            "recovery_attempt"
        ] = attempt

        recovery_message[
            "recovery_run_id"
        ] = run_id

        recovery_message[
            "recovery_timestamp_ms"
        ] = epoch_ms()

        recovery_message[
            "recovery_timestamp"
        ] = (
            datetime.now(
                timezone.utc
            ).isoformat()
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
                ).decode(
                    "utf-8"
                ),

            "signature_b64":
                base64.b64encode(
                    signature
                ).decode(
                    "utf-8"
                ),

            "public_key_b64":
                base64.b64encode(
                    public_key
                ).decode(
                    "utf-8"
                ),

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
                epoch_ms(),

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
        max_retries,
        recovery_timeout,
        poll_interval,
        run_id
    ):

        remaining = set(
            initial_missing_ids
        )

        recovery_transaction_ids = []

        recovered_original_ids = set()

        recovery_history = []

        latest_tx_by_original = {}

        recovery_start = now()

        for attempt in range(
            1,
            max_retries + 1
        ):

            if not remaining:
                break

            print()
            print("=" * 80)

            print(
                f"RECOVERY RUN {run_id} | "
                f"ATTEMPT {attempt}"
            )

            print("=" * 80)

            committed_now = (
                read_committed_transaction_ids(
                    PBFT_METRICS_FILE
                )
            )

            already_recovered = (
                remaining &
                committed_now
            )

            if already_recovered:

                recovered_original_ids.update(
                    already_recovered
                )

                remaining -= (
                    already_recovered
                )

                if not remaining:
                    break

            attempt_tx_ids = []

            for original_id in sorted(
                remaining
            ):

                original_payload = (
                    submitted_payloads.get(
                        original_id
                    )
                )

                if original_payload is None:

                    recovery_history.append(
                        {
                            "run_id": run_id,
                            "original_transaction_id":
                                original_id,
                            "recovery_attempt":
                                attempt,
                            "recovery_transaction_id":
                                "",
                            "published":
                                False,
                            "committed":
                                False,
                            "error":
                                "Original payload unavailable"
                        }
                    )

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

                    published = (
                        publish_payload(
                            recovery_payload
                        )
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
                                "published":
                                    True,
                                "committed":
                                    False
                            }
                        )

                    else:

                        recovery_history.append(
                            {
                                "run_id": run_id,
                                "original_transaction_id":
                                    original_id,
                                "recovery_attempt":
                                    attempt,
                                "recovery_transaction_id":
                                    recovery_tx_id,
                                "published":
                                    False,
                                "committed":
                                    False,
                                "error":
                                    "MQTT publish failed"
                            }
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
                            "published":
                                False,
                            "committed":
                                False,
                            "error":
                                str(error)
                        }
                    )

            if attempt_tx_ids:

                (
                    recovery_committed,
                    recovery_missing,
                    elapsed
                ) = wait_for_pbft_completion(
                    attempt_tx_ids,
                    PBFT_METRICS_FILE,
                    recovery_timeout,
                    poll_interval
                )

                committed_tx_set = set(
                    recovery_committed
                )

                for tx_id in attempt_tx_ids:

                    for record in recovery_history:

                        if record.get(
                            "recovery_transaction_id"
                        ) == tx_id:

                            record[
                                "committed"
                            ] = (
                                tx_id
                                in
                                committed_tx_set
                            )

                            if record[
                                "committed"
                            ]:

                                recovered_original_ids.add(
                                    record[
                                        "original_transaction_id"
                                    ]
                                )

                remaining -= (
                    recovered_original_ids
                )

            else:

                print(
                    f"⚠️ No recovery transactions "
                    f"were published in attempt {attempt}"
                )

        recovery_time_sec = (
            now()
            -
            recovery_start
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
                recovery_time_sec
        }

    # ========================================================
    # RUN LOOP
    # ========================================================

    try:

        for run_id in range(
            1,
            RUNS + 1
        ):

            print()
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

            successful_transactions = []

            transaction_id_set = set()

            submitted_payloads = {}

            user_stopped = False

            # ------------------------------------------------
            # IMAGE LOOP
            # ------------------------------------------------

            for image_index, image_path in enumerate(
                image_files,
                start=1
            ):

                print()
                print("-" * 90)

                print(
                    f"[Run {run_id}/{RUNS}] "
                    f"[{image_index}/{len(image_files)}] "
                    f"Processing: {image_path.name}"
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

                result = None

                # --------------------------------------------
                # READ
                # --------------------------------------------

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
                        transaction_id,
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
                        transaction_id,
                        "image_read",
                        "cv2.imread returned None"
                    )

                    continue

                # --------------------------------------------
                # FRAME ID
                # --------------------------------------------

                if args.dataset == "mot17":

                    try:

                        frame_id = int(
                            image_path.stem
                        )

                    except ValueError:

                        frame_id = image_index

                # --------------------------------------------
                # TX ID
                # --------------------------------------------

                transaction_id = (
                    uuid.uuid4().hex
                )

                if (
                    transaction_id
                    in
                    transaction_id_set
                ):

                    failed_images += 1

                    record_failure(
                        run_id,
                        image_index,
                        image_path,
                        transaction_id,
                        "transaction_id",
                        "Duplicate transaction ID generated",
                        frame_id
                    )

                    continue

                transaction_id_set.add(
                    transaction_id
                )

                # --------------------------------------------
                # TIMESTAMP
                # --------------------------------------------

                source_timestamp_ms = (
                    epoch_ms()
                )

                source_timestamp_iso = (
                    datetime.now(
                        timezone.utc
                    ).isoformat()
                )

                # --------------------------------------------
                # YOLO
                # --------------------------------------------

                try:

                    synchronize_cuda()

                    inference_start = now()

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

                    inference_time = (
                        now()
                        -
                        inference_start
                    )

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

                # --------------------------------------------
                # POST PROCESSING
                # --------------------------------------------

                try:

                    post_start = now()

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

                                "class_id":
                                    cls_id,

                                "class":
                                    result.names[
                                        cls_id
                                    ],

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

                    post_time = (
                        now()
                        -
                        post_start
                    )

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

                # --------------------------------------------
                # MESSAGE
                # --------------------------------------------

                try:

                    json_start = now()

                    message = {

                        "schema_version":
                            "1.1",

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
                                    ms(
                                        inference_time
                                    ),

                                "postprocessing_ms":
                                    ms(
                                        post_time
                                    )
                            }
                    }

                    message_bytes = json.dumps(
                        message,
                        sort_keys=True,
                        separators=(",", ":")
                    ).encode(
                        "utf-8"
                    )

                    json_time = (
                        now()
                        -
                        json_start
                    )

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

                # --------------------------------------------
                # PQC
                # --------------------------------------------

                sig_ptr = (
                    ctypes.POINTER(
                        ctypes.c_ubyte
                    )()
                )

                pk_ptr = (
                    ctypes.POINTER(
                        ctypes.c_ubyte
                    )()
                )

                sig_len = (
                    ctypes.c_size_t()
                )

                pk_len = (
                    ctypes.c_size_t()
                )

                try:

                    sign_start = now()

                    ret = lib.pqc_sign(

                        message_bytes,

                        len(message_bytes),

                        PQC_ALGO_CODE,

                        ctypes.byref(
                            sig_ptr
                        ),

                        ctypes.byref(
                            sig_len
                        ),

                        ctypes.byref(
                            pk_ptr
                        ),

                        ctypes.byref(
                            pk_len
                        )
                    )

                    pqc_time = (
                        now()
                        -
                        sign_start
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

                if ret != 0:

                    failed_images += 1

                    record_failure(
                        run_id,
                        image_index,
                        image_path,
                        transaction_id,
                        "pqc_signing",
                        f"pqc_sign returned error code {ret}",
                        frame_id
                    )

                    continue

                try:

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
                        "pqc_memory",
                        error,
                        frame_id
                    )

                    continue

                finally:

                    try:

                        if bool(sig_ptr):

                            lib.pqc_free(
                                sig_ptr
                            )

                    except Exception:
                        pass

                    try:

                        if bool(pk_ptr):

                            lib.pqc_free(
                                pk_ptr
                            )

                    except Exception:
                        pass

                # --------------------------------------------
                # PAYLOAD
                # --------------------------------------------

                try:

                    payload = {

                        "transaction_id":
                            transaction_id,

                        "message_b64":
                            base64.b64encode(
                                message_bytes
                            ).decode(
                                "utf-8"
                            ),

                        "signature_b64":
                            base64.b64encode(
                                signature
                            ).decode(
                                "utf-8"
                            ),

                        "public_key_b64":
                            base64.b64encode(
                                public_key
                            ).decode(
                                "utf-8"
                            ),

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
                                    ms(
                                        inference_time
                                    ),

                                "postprocessing_ms":
                                    ms(
                                        post_time
                                    ),

                                "json_generation_ms":
                                    ms(
                                        json_time
                                    ),

                                "pqc_signing_ms":
                                    ms(
                                        pqc_time
                                    )
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

                # --------------------------------------------
                # MQTT
                # --------------------------------------------

                try:

                    mqtt_start = now()

                    if not client.is_connected():

                        try:
                            client.reconnect()
                        except Exception:
                            pass

                        reconnect_deadline = (
                            time.time()
                            +
                            5
                        )

                        while (
                            not client.is_connected()
                            and
                            time.time()
                            <
                            reconnect_deadline
                        ):

                            time.sleep(
                                0.05
                            )

                    if not client.is_connected():

                        failed_images += 1

                        record_failure(
                            run_id,
                            image_index,
                            image_path,
                            transaction_id,
                            "mqtt_connection",
                            "MQTT is not connected",
                            frame_id
                        )

                        continue

                    mqtt_info = client.publish(
                        MQTT_TOPIC,
                        payload_json,
                        qos=1,
                        retain=False
                    )

                    mqtt_info.wait_for_publish()

                    if (
                        mqtt_info.rc
                        !=
                        mqtt.MQTT_ERR_SUCCESS
                    ):

                        failed_images += 1

                        record_failure(
                            run_id,
                            image_index,
                            image_path,
                            transaction_id,
                            "mqtt_publish",
                            (
                                "MQTT publish returned "
                                f"error code {mqtt_info.rc}"
                            ),
                            frame_id
                        )

                        continue

                    mqtt_time = (
                        now()
                        -
                        mqtt_start
                    )

                except Exception as error:

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

                # --------------------------------------------
                # PIPELINE
                # --------------------------------------------

                pipeline_time = (
                    now()
                    -
                    pipeline_start
                )

                submitted_transaction_ids.append(
                    transaction_id
                )

                successful_transactions.append(
                    transaction_id
                )

                submitted_payloads[
                    transaction_id
                ] = payload.copy()

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

                total_detections += (
                    detection_count
                )

                # --------------------------------------------
                # CSV
                # --------------------------------------------

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
                                if
                                SEQUENCE_NAME
                                is not None
                                else ""
                            ),

                        "image_index":
                            image_index,

                        "frame_id":
                            (
                                frame_id
                                if
                                frame_id is not None
                                else ""
                            ),

                        "image":
                            image_path.name,

                        "detection_count":
                            detection_count,

                        "yolo_inference_ms":
                            ms(
                                inference_time
                            ),

                        "postprocessing_ms":
                            ms(
                                post_time
                            ),

                        "json_generation_ms":
                            ms(
                                json_time
                            ),

                        "pqc_signing_ms":
                            ms(
                                pqc_time
                            ),

                        "mqtt_transmission_ms":
                            ms(
                                mqtt_time
                            ),

                        "python_pipeline_ms":
                            ms(
                                pipeline_time
                            ),

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

                # --------------------------------------------
                # PRINT
                # --------------------------------------------

                print(
                    f"📷 Camera       : {CAMERA_ID}"
                )

                print(
                    f"📚 Dataset      : {DATASET_NAME}"
                )

                print(
                    f"🔁 Run          : {run_id}/{RUNS}"
                )

                print(
                    f"🆔 TX ID        : {transaction_id}"
                )

                print(
                    f"🖼️ Image        : {image_path.name}"
                )

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
                    f"📡 MQTT publish : "
                    f"{ms(mqtt_time)} ms"
                )

                print(
                    f"⏱️ Python pipe  : "
                    f"{ms(pipeline_time)} ms"
                )

                print(
                    "📤 Status       : "
                    "SUBMITTED TO MQTT"
                )

                # --------------------------------------------
                # DISPLAY
                # --------------------------------------------

                if not args.no_display:

                    try:

                        annotated = (
                            result.plot()
                        )

                        cv2.putText(
                            annotated,
                            f"Run: {run_id}",
                            (20, 30),
                            cv2.FONT_HERSHEY_SIMPLEX,
                            0.7,
                            (0, 255, 0),
                            2
                        )

                        cv2.putText(
                            annotated,
                            f"Camera: {CAMERA_ID}",
                            (20, 60),
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

                # --------------------------------------------
                # FPS LIMIT
                # --------------------------------------------

                if (
                    TARGET_FPS
                    and
                    TARGET_FPS > 0
                ):

                    elapsed = (
                        now()
                        -
                        pipeline_start
                    )

                    interval = (
                        1.0 /
                        TARGET_FPS
                    )

                    sleep_time = (
                        interval
                        -
                        elapsed
                    )

                    if sleep_time > 0:

                        time.sleep(
                            sleep_time
                        )

                # --------------------------------------------
                # ESC
                # --------------------------------------------

                if not args.no_display:

                    key = (
                        cv2.waitKey(1)
                        &
                        0xFF
                    )

                    if key == 27:

                        user_stopped = True

                        break

            # =================================================
            # PBFT DRAIN
            # =================================================

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

            # =================================================
            # RECOVERY
            # =================================================

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

            final_committed_metrics = (
                read_committed_transaction_ids(
                    PBFT_METRICS_FILE
                )
            )

            final_recovered_original_ids = set()

            for original_id in initial_missing_ids:

                latest_id = (
                    latest_tx_by_original.get(
                        original_id,
                        original_id
                    )
                )

                if (
                    latest_id
                    in
                    final_committed_metrics
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

            # =================================================
            # RUN END
            # =================================================

            run_end = now()

            run_time = (
                run_end
                -
                run_start
            )

            python_fps = 0.0
            detection_rate = 0.0

            if run_time > 0:

                python_fps = (
                    processed_images
                    /
                    run_time
                )

                detection_rate = (
                    total_detections
                    /
                    run_time
                )

            # =================================================
            # RUN SUMMARY
            # =================================================

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

            # =================================================
            # PBFT SUMMARY
            # =================================================

            for original_id in (
                submitted_transaction_ids
            ):

                if original_id in (
                    initial_committed_ids
                ):

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
                        for r
                        in recovery_history

                        if r.get(
                            "original_transaction_id"
                        )
                        ==
                        original_id
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
                                            if
                                            original_id
                                            in
                                            recovered_original_ids
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

            # =================================================
            # STATISTICS
            # =================================================

            components = [

                (
                    "YOLO inference",
                    inference_times
                ),

                (
                    "Post-processing",
                    postprocess_times
                ),

                (
                    "JSON generation",
                    json_times
                ),

                (
                    "PQC signing",
                    pqc_times
                ),

                (
                    "MQTT publish/wait",
                    mqtt_times
                ),

                (
                    "Python pipeline",
                    pipeline_times
                )
            ]

            for component, values in components:

                summary = (
                    statistics_summary(
                        values
                    )
                )

                summary_writer.writerow(
                    {

                        "run_id":
                            run_id,

                        "component":
                            component,

                        "mean_ms":
                            summary[
                                "mean_ms"
                            ],

                        "median_ms":
                            summary[
                                "median_ms"
                            ],

                        "std_ms":
                            summary[
                                "std_ms"
                            ],

                        "p95_ms":
                            summary[
                                "p95_ms"
                            ],

                        "p99_ms":
                            summary[
                                "p99_ms"
                            ],

                        "min_ms":
                            summary[
                                "min_ms"
                            ],

                        "max_ms":
                            summary[
                                "max_ms"
                            ]
                    }
                )

            summary_file.flush()

            # =================================================
            # METADATA
            # =================================================

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

                    "detection_rate_per_sec":
                        round(
                            detection_rate,
                            6
                        ),

                    "user_stopped":
                        user_stopped
                }
            )

            if user_stopped:
                break

    finally:

        try:
            csv_file.flush()
            csv_file.close()
        except Exception:
            pass

        try:
            summary_file.flush()
            summary_file.close()
        except Exception:
            pass

        try:
            run_summary_file.flush()
            run_summary_file.close()
        except Exception:
            pass

        try:
            pbft_summary_file.flush()
            pbft_summary_file.close()
        except Exception:
            pass

        # ====================================================
        # FAILED CSV
        # ====================================================

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
                "⚠️ Could not write failed-frame CSV:",
                error
            )

        # ====================================================
        # FINAL METADATA
        # ====================================================

        total_experiment_time = (
            now()
            -
            global_start
        )

        metadata = {

            "schema_version":
                "D.1",

            "experiment":
                "Experiment D",

            "description":
                "YOLOv8 + MQTT + PQC + PBFT-style Blockchain",

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
                str(
                    CSV_PATH
                ),

            "summary_csv":
                str(
                    SUMMARY_CSV_PATH
                ),

            "run_summary_csv":
                str(
                    RUN_SUMMARY_PATH
                ),

            "failed_frames_csv":
                str(
                    FAILED_CSV_PATH
                ),

            "pbft_commit_summary_csv":
                str(
                    PBFT_RESULT_PATH
                )
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

        if not args.no_display:

            try:
                cv2.destroyAllWindows()
            except Exception:
                pass

        try:
            client.loop_stop()
        except Exception:
            pass

        try:
            client.disconnect()
        except Exception:
            pass

    print()
    print("=" * 90)

    print(
        "EXPERIMENT D COMPLETED"
    )

    print("=" * 90)

    print(
        "Requested independent runs :",
        RUNS
    )

    print(
        "Completed runs              :",
        len(
            all_run_metadata
        )
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
        "Statistical summary         :",
        SUMMARY_CSV_PATH
    )

    print(
        "Run summary                 :",
        RUN_SUMMARY_PATH
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
        "PBFT canonical metrics      :",
        PBFT_METRICS_FILE
    )

    print("=" * 90)


# ============================================================
# IMAGE EXTENSIONS
# ============================================================

IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".webp"
}


# ============================================================
# GLOBAL MQTT / MODEL INITIALIZATION
# ============================================================

mqtt_connected = False


def on_global_connect(
    client_obj,
    userdata,
    flags,
    rc
):

    global mqtt_connected

    mqtt_connected = (
        rc == 0
    )


def on_global_disconnect(
    client_obj,
    userdata,
    rc
):

    global mqtt_connected

    mqtt_connected = False


# ============================================================
# INITIALIZE IMAGE LIST / MODEL / MQTT / PQC
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
            and
            path.suffix.lower()
            in IMAGE_EXTENSIONS
        )
    ]
)

if not image_files:

    raise RuntimeError(
        "No supported images were found in:\n"
        f"{IMAGE_FOLDER}"
    )

if args.max_images > 0:

    image_files = image_files[
        :args.max_images
    ]


device = (
    "cuda"
    if torch.cuda.is_available()
    else "cpu"
)

half = (
    device == "cuda"
)


def synchronize_cuda():

    if (
        device == "cuda"
        and
        torch.cuda.is_available()
    ):

        torch.cuda.synchronize()


client = mqtt.Client(
    client_id=(
        f"yolo-security-{CAMERA_ID}-"
        f"{uuid.uuid4().hex[:8]}"
    )
)

client.on_connect = on_global_connect
client.on_disconnect = on_global_disconnect

client.reconnect_delay_set(
    min_delay=1,
    max_delay=10
)

client.connect(
    MQTT_BROKER,
    MQTT_PORT,
    keepalive=60
)

client.loop_start()

deadline = (
    time.time()
    +
    10
)

while (
    not mqtt_connected
    and
    time.time()
    <
    deadline
):

    time.sleep(
        0.05
    )

if not mqtt_connected:

    client.loop_stop()

    raise RuntimeError(
        "Unable to connect to MQTT broker"
    )


if not Path(
    PQC_LIBRARY
).exists():

    client.loop_stop()

    raise FileNotFoundError(
        f"PQC shared library not found:\n{PQC_LIBRARY}"
    )


lib = ctypes.CDLL(
    PQC_LIBRARY
)

lib.pqc_sign.argtypes = [

    ctypes.c_char_p,

    ctypes.c_size_t,

    ctypes.c_char,

    ctypes.POINTER(
        ctypes.POINTER(
            ctypes.c_ubyte
        )
    ),

    ctypes.POINTER(
        ctypes.c_size_t
    ),

    ctypes.POINTER(
        ctypes.POINTER(
            ctypes.c_ubyte
        )
    ),

    ctypes.POINTER(
        ctypes.c_size_t
    )
]

lib.pqc_sign.restype = (
    ctypes.c_int
)

lib.pqc_free.argtypes = [

    ctypes.POINTER(
        ctypes.c_ubyte
    )
]

lib.pqc_free.restype = None


model = YOLO(
    MODEL_PATH
)

model.to(
    device
)

synchronize_cuda()


warmup_image = cv2.imread(
    str(image_files[0])
)

if warmup_image is not None:

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


# ============================================================
# MAIN DISPATCH
# ============================================================

try:

    if SECURITY_MODE:

        initialize_security_csv()

        run_security_experiment()

    else:

        run_normal_experiment()

finally:

    try:
        client.loop_stop()
    except Exception:
        pass

    try:
        client.disconnect()
    except Exception:
        pass
