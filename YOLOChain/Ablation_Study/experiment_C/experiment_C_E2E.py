#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
YOLOChain
Experiment C — End-to-End Latency Measurement

Architecture:
    YOLOv8
       |
      MQTT QoS 1
       |
    Validator / P2P
       |
      PBFT
       |
    Canonical Blockchain Commit

PRIMARY E2E DEFINITION
----------------------
E2E latency =
    YOLO inference START
        ->
    canonical blockchain COMMIT

The E2E value is measured directly from timestamps.

It is NOT calculated as:

    YOLO + MQTT + PBFT

Component metrics are reported independently.

Experiment C:
    YOLOv8 + MQTT + Blockchain/PBFT

Security:
    PQC       = OFF
    KEM       = OFF
    AES       = OFF
    Signature = OFF

PBFT:
    N = 4
    F = 1
    quorum = 3

Canonical commit source:
    results_C_fixed/validator_1/results/commit_events.csv

PBFT source:
    results_C_fixed/validator_1/results/pbft_metrics.csv

No dependency on:
    commit_ids.log
    blockchain.json
"""

import os
import sys
import csv
import json
import time
import math
import argparse
import statistics
import threading
from datetime import datetime, timezone

import cv2
import numpy as np
import paho.mqtt.client as mqtt

from ultralytics import YOLO


# ============================================================
# DEFAULT CONFIGURATION
# ============================================================

DEFAULT_DATASET = "coco128"

DEFAULT_MODEL = "yolov8n.pt"

DEFAULT_INPUT_DIR = (
    "/home/saif/ownblockchain/pk_p2p/hand_shake_peers/"
    "gui/pqc/bc_5_9_2026/coco128/images/train2017"
)

DEFAULT_BROKER = "127.0.0.1"
DEFAULT_PORT = 1883
DEFAULT_TOPIC = "yolochain/C"
DEFAULT_MQTT_QOS = 1

DEFAULT_RESULTS_DIR = "results_C_E2E_COCO128"
DEFAULT_CANONICAL_RESULTS_DIR = "results_C_fixed"

DEFAULT_CAMERA_ID = "camera_01"

DEFAULT_VALIDATOR_ID = "validator_1"

IMAGE_SIZE = 416
CONF_THRESHOLD = 0.25
IOU_THRESHOLD = 0.50

WARMUP = 10
RUNS = 5

NETWORK_READY_TIMEOUT_SEC = 30.0
COMMIT_TIMEOUT_SEC = 30.0
COMMIT_FILE_TIMEOUT_SEC = 30.0

POLL_INTERVAL_SEC = 0.01

PBFT_N = 4
PBFT_F = 1
PBFT_QUORUM = 3


# ============================================================
# MQTT GLOBAL
# ============================================================

mqtt_client = None
mqtt_connected = threading.Event()


# ============================================================
# ARGUMENT PARSER
# ============================================================

def parse_args():

    parser = argparse.ArgumentParser(
        description=(
            "YOLOChain Experiment C — "
            "YOLO start to canonical blockchain commit"
        )
    )

    parser.add_argument(
        "--dataset",
        default=DEFAULT_DATASET,
        help="Dataset name"
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        help="YOLO model path"
    )

    parser.add_argument(
        "--input-dir",
        default=DEFAULT_INPUT_DIR,
        help="Input image directory"
    )

    parser.add_argument(
        "--broker",
        default=DEFAULT_BROKER,
        help="MQTT broker address"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="MQTT broker port"
    )

    parser.add_argument(
        "--topic",
        default=DEFAULT_TOPIC,
        help="MQTT topic"
    )

    parser.add_argument(
        "--mqtt-qos",
        type=int,
        choices=[0, 1, 2],
        default=DEFAULT_MQTT_QOS,
        help="MQTT QoS"
    )

    parser.add_argument(
        "--results-dir",
        default=DEFAULT_RESULTS_DIR,
        help="Directory for new E2E results"
    )

    parser.add_argument(
        "--canonical-results-dir",
        default=DEFAULT_CANONICAL_RESULTS_DIR,
        help=(
            "Directory containing validator canonical "
            "commit_events.csv and pbft_metrics.csv"
        )
    )

    parser.add_argument(
        "--camera-id",
        default=DEFAULT_CAMERA_ID,
        help="Camera identifier"
    )

    parser.add_argument(
        "--validator-id",
        default=DEFAULT_VALIDATOR_ID,
        help="Canonical validator identifier"
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=RUNS,
        help="Number of independent runs"
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=WARMUP,
        help="Number of YOLO warm-up iterations"
    )

    parser.add_argument(
        "--commit-timeout",
        type=float,
        default=COMMIT_TIMEOUT_SEC,
        help="Maximum wait for canonical commit per transaction"
    )

    return parser.parse_args()


# ============================================================
# TIME HELPERS
# ============================================================

def epoch_ms():
    """
    Wall-clock epoch timestamp in milliseconds.

    This is intentionally used for the E2E cross-process
    timestamp because the camera process and validator process
    must share a comparable wall-clock time base.
    """

    return time.time() * 1000.0


def utc_now_iso():
    return datetime.now(
        timezone.utc
    ).isoformat()


# ============================================================
# STATISTICS
# ============================================================

def mean(values):

    if not values:
        return float("nan")

    return float(
        statistics.mean(values)
    )


def sd(values):

    if len(values) < 2:
        return 0.0

    return float(
        statistics.stdev(values)
    )


def percentile(values, p):

    if not values:
        return float("nan")

    return float(
        np.percentile(
            np.asarray(
                values,
                dtype=float
            ),
            p
        )
    )


def ci95_t(values):
    """
    95% confidence interval over independent run means.

    For n = 5:
        t(0.975, 4) = 2.776445
    """

    n = len(values)

    if n < 2:
        return (
            float("nan"),
            float("nan")
        )

    m = mean(values)
    s = sd(values)

    t_table = {
        2: 12.706205,
        3: 4.302653,
        4: 3.182446,
        5: 2.776445,
        6: 2.570582,
        7: 2.446912,
        8: 2.364624,
        9: 2.306004,
        10: 2.262157
    }

    tcrit = t_table.get(
        n,
        1.96
    )

    margin = (
        tcrit *
        s /
        math.sqrt(n)
    )

    return (
        m - margin,
        m + margin
    )


def equivalent_fps(latency_ms):

    if (
        latency_ms is None
        or not math.isfinite(latency_ms)
        or latency_ms <= 0
    ):
        return float("nan")

    return 1000.0 / latency_ms


# ============================================================
# FILE HELPERS
# ============================================================

def ensure_dir(path):
    os.makedirs(
        path,
        exist_ok=True
    )


def read_csv_rows(path):

    if not os.path.exists(path):
        return []

    try:

        with open(
            path,
            "r",
            newline="",
            encoding="utf-8"
        ) as f:

            reader = csv.DictReader(f)

            return list(reader)

    except Exception as e:

        print(
            "[WARN] Could not read:",
            path
        )

        print(
            "       ",
            str(e)
        )

        return []


# ============================================================
# CANONICAL PATHS
# ============================================================

def build_canonical_paths(
    canonical_results_dir,
    validator_id
):

    validator_results = os.path.join(
        canonical_results_dir,
        validator_id,
        "results"
    )

    commit_events = os.path.join(
        validator_results,
        "commit_events.csv"
    )

    pbft_metrics = os.path.join(
        validator_results,
        "pbft_metrics.csv"
    )

    ready_flag = os.path.join(
        canonical_results_dir,
        "network",
        "ready.flag"
    )

    return (
        commit_events,
        pbft_metrics,
        ready_flag
    )


# ============================================================
# NETWORK
# ============================================================

def wait_for_network_ready(
    ready_flag,
    timeout_sec
):

    print()
    print(
        "[NETWORK] Waiting for PBFT network..."
    )

    print(
        "[NETWORK] ready.flag:"
    )

    print(
        "           ",
        ready_flag
    )

    deadline = (
        time.monotonic() +
        timeout_sec
    )

    while time.monotonic() < deadline:

        if os.path.exists(
            ready_flag
        ):

            print(
                "[NETWORK] Ready."
            )

            return True

        time.sleep(0.2)

    return False


# ============================================================
# COMMIT EVENTS
# ============================================================

def wait_for_commit_file(
    commit_events_file,
    timeout_sec
):

    deadline = (
        time.monotonic() +
        timeout_sec
    )

    while time.monotonic() < deadline:

        if os.path.exists(
            commit_events_file
        ):
            return True

        time.sleep(
            POLL_INTERVAL_SEC
        )

    return False


def get_commit_event(
    commit_events_file,
    tx_id
):

    rows = read_csv_rows(
        commit_events_file
    )

    for row in rows:

        if row.get("tx_id") == tx_id:

            return row

    return None


def parse_float(value):

    if value is None:
        return None

    if str(value).strip() == "":
        return None

    try:
        return float(value)

    except Exception:
        return None


def get_commit_timestamp_ms(
    commit_row
):

    if commit_row is None:
        return None

    return parse_float(
        commit_row.get(
            "commit_timestamp_ms"
        )
    )


def wait_for_canonical_commit(
    commit_events_file,
    tx_id,
    timeout_sec
):

    deadline = (
        time.monotonic() +
        timeout_sec
    )

    while time.monotonic() < deadline:

        row = get_commit_event(
            commit_events_file,
            tx_id
        )

        if row is not None:

            timestamp_ms = (
                get_commit_timestamp_ms(
                    row
                )
            )

            if timestamp_ms is not None:

                return row

        time.sleep(
            POLL_INTERVAL_SEC
        )

    return None


# ============================================================
# PBFT METRICS
# ============================================================

def get_pbft_row(
    pbft_metrics_file,
    tx_id
):

    rows = read_csv_rows(
        pbft_metrics_file
    )

    selected = None

    for row in rows:

        if row.get("tx_id") == tx_id:

            selected = row

    return selected


def extract_pbft_metrics(
    pbft_metrics_file,
    tx_id
):

    row = get_pbft_row(
        pbft_metrics_file,
        tx_id
    )

    if row is None:

        return {
            "pbft_preprepare_ms": None,
            "pbft_prepare_ms": None,
            "pbft_commit_ms": None,
            "pbft_total_ms": None,
            "prepare_quorum": None,
            "commit_quorum": None,
            "N": None,
            "F": None,
            "block_index": None,
            "blockchain_length": None,
            "recovery_of": None,
            "recovery_attempt": None
        }

    return {
        "pbft_preprepare_ms":
            parse_float(
                row.get(
                    "pbft_preprepare_ms"
                )
            ),

        "pbft_prepare_ms":
            parse_float(
                row.get(
                    "pbft_prepare_ms"
                )
            ),

        "pbft_commit_ms":
            parse_float(
                row.get(
                    "pbft_commit_ms"
                )
            ),

        "pbft_total_ms":
            parse_float(
                row.get(
                    "pbft_total_ms"
                )
            ),

        "prepare_quorum":
            row.get(
                "prepare_quorum"
            ),

        "commit_quorum":
            row.get(
                "commit_quorum"
            ),

        "N":
            row.get(
                "N"
            ),

        "F":
            row.get(
                "F"
            ),

        "block_index":
            row.get(
                "block_index"
            ),

        "blockchain_length":
            row.get(
                "blockchain_length"
            ),

        "recovery_of":
            row.get(
                "recovery_of"
            ),

        "recovery_attempt":
            row.get(
                "recovery_attempt"
            )
    }


# ============================================================
# MQTT CALLBACKS
# ============================================================

def on_connect(
    client,
    userdata,
    flags,
    rc,
    properties=None
):

    if rc == 0:

        mqtt_connected.set()

        print(
            "[MQTT] Connected to "
            f"{MQTT_HOST_RUNTIME}:"
            f"{MQTT_PORT_RUNTIME}"
        )

    else:

        print(
            "[MQTT] Connection failed:",
            rc
        )


def on_disconnect(
    client,
    userdata,
    rc,
    properties=None
):

    mqtt_connected.clear()

    print(
        "[MQTT] Disconnected:",
        rc
    )


# Runtime MQTT configuration.
MQTT_HOST_RUNTIME = DEFAULT_BROKER
MQTT_PORT_RUNTIME = DEFAULT_PORT


def setup_mqtt(
    broker,
    port
):

    global mqtt_client
    global MQTT_HOST_RUNTIME
    global MQTT_PORT_RUNTIME

    MQTT_HOST_RUNTIME = broker
    MQTT_PORT_RUNTIME = port

    try:

        mqtt_client = mqtt.Client(
            client_id=(
                "YOLOChain_C_E2E_Camera"
            )
        )

    except TypeError:

        mqtt_client = mqtt.Client()

    mqtt_client.on_connect = on_connect
    mqtt_client.on_disconnect = on_disconnect

    mqtt_client.connect(
        broker,
        port,
        keepalive=60
    )

    mqtt_client.loop_start()

    if not mqtt_connected.wait(
        timeout=10.0
    ):

        raise RuntimeError(
            "MQTT connection timeout"
        )


def shutdown_mqtt():

    global mqtt_client

    if mqtt_client is None:
        return

    try:
        mqtt_client.loop_stop()
    except Exception:
        pass

    try:
        mqtt_client.disconnect()
    except Exception:
        pass

    mqtt_client = None


# ============================================================
# MQTT PUBLISH
# ============================================================

def publish_transaction(
    payload,
    topic,
    qos
):

    payload_text = json.dumps(
        payload,
        separators=(",", ":"),
        ensure_ascii=False
    )

    start = time.perf_counter()

    info = mqtt_client.publish(
        topic,
        payload_text,
        qos=qos,
        retain=False
    )

    call_end = time.perf_counter()

    mqtt_publish_call_ms = (
        call_end -
        start
    ) * 1000.0

    mqtt_publish_completion_ms = None

    try:

        info.wait_for_publish(
            timeout=10.0
        )

        completion_end = (
            time.perf_counter()
        )

        mqtt_publish_completion_ms = (
            completion_end -
            start
        ) * 1000.0

    except Exception as e:

        print(
            "[WARN] MQTT publish completion:",
            str(e)
        )

    return (
        mqtt_publish_call_ms,
        mqtt_publish_completion_ms
    )


# ============================================================
# SHA-256
# ============================================================

def sha256_text(text):

    import hashlib

    return hashlib.sha256(
        text.encode(
            "utf-8"
        )
    ).hexdigest()


# ============================================================
# YOLO
# ============================================================

def extract_detections(result):

    detections = []

    if result.boxes is None:
        return detections

    boxes = result.boxes

    for i in range(
        len(boxes)
    ):

        xyxy = (
            boxes.xyxy[i]
            .tolist()
        )

        confidence = float(
            boxes.conf[i].item()
        )

        class_id = int(
            boxes.cls[i].item()
        )

        detections.append(
            {
                "class_id":
                    class_id,

                "confidence":
                    confidence,

                "bbox":
                    [
                        float(x)
                        for x in xyxy
                    ]
            }
        )

    return detections


def create_transaction(
    dataset,
    camera_id,
    sequence,
    frame_id,
    frame_file,
    image_index,
    run_id,
    detections,
    source_timestamp_ms
):

    tx_id = (
        f"{camera_id}_"
        f"run{run_id}_"
        f"seq{sequence}_"
        f"{int(time.time() * 1000)}"
    )

    payload = {

        "experiment":
            "C",

        "dataset":
            dataset,

        "camera_id":
            camera_id,

        "sequence":
            sequence,

        "frame_id":
            frame_id,

        "frame_file":
            frame_file,

        "image_index":
            image_index,

        "run":
            run_id,

        "tx_id":
            tx_id,

        "timestamp_utc":
            utc_now_iso(),

        "source_timestamp_ms":
            source_timestamp_ms,

        "model":
            "YOLOv8n",

        "image_size":
            IMAGE_SIZE,

        "confidence_threshold":
            CONF_THRESHOLD,

        "iou_threshold":
            IOU_THRESHOLD,

        "detection_count":
            len(detections),

        "detections":
            detections,

        "pqc":
            False,

        "kem":
            False,

        "aes":
            False,

        "signature":
            False,

        "architecture":
            "YOLOv8+MQTT+P2P+PBFT-style+local-blockchain"
    }

    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    )

    payload["digest"] = sha256_text(
        canonical
    )

    return payload


# ============================================================
# IMAGE LIST
# ============================================================

def get_images(
    input_dir
):

    extensions = (
        ".jpg",
        ".jpeg",
        ".png",
        ".bmp",
        ".webp"
    )

    files = []

    for filename in os.listdir(
        input_dir
    ):

        if filename.lower().endswith(
            extensions
        ):

            files.append(
                os.path.join(
                    input_dir,
                    filename
                )
            )

    files.sort()

    return files


# ============================================================
# OUTPUT FILES
# ============================================================

def initialize_outputs(
    results_dir
):

    ensure_dir(
        results_dir
    )

    frame_file = os.path.join(
        results_dir,
        "C_E2E_frame_level_raw.csv"
    )

    run_file = os.path.join(
        results_dir,
        "C_E2E_run_summary.csv"
    )

    frame_fields = [

        "dataset",
        "run",
        "image_index",
        "frame_id",
        "frame_file",

        "camera_id",
        "sequence",
        "tx_id",

        "yolo_start_epoch_ms",
        "canonical_commit_epoch_ms",

        "e2e_latency_ms",

        "yolo_inference_ms",
        "postprocessing_ms",
        "json_generation_ms",

        "mqtt_publish_call_ms",
        "mqtt_publish_completion_ms",

        "pbft_preprepare_ms",
        "pbft_prepare_ms",
        "pbft_commit_ms",
        "pbft_total_ms",

        "prepare_quorum",
        "commit_quorum",

        "N",
        "F",

        "block_index",
        "blockchain_length",

        "recovery_of",
        "recovery_attempt",

        "commit_status"
    ]

    with open(
        frame_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=frame_fields
        )

        writer.writeheader()

    run_fields = [

        "dataset",
        "run",

        "frames_attempted",
        "frames_committed",
        "frames_failed",

        "e2e_mean_ms",
        "e2e_sd_ms",
        "e2e_p95_ms",
        "e2e_p99_ms",

        "equivalent_fps",

        "yolo_mean_ms",
        "postprocessing_mean_ms",
        "json_generation_mean_ms",

        "mqtt_publish_call_mean_ms",
        "mqtt_publish_completion_mean_ms",

        "pbft_preprepare_mean_ms",
        "pbft_prepare_mean_ms",
        "pbft_commit_mean_ms",
        "pbft_total_mean_ms"
    ]

    with open(
        run_file,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=run_fields
        )

        writer.writeheader()

    return (
        frame_file,
        run_file
    )


def append_csv_row(
    path,
    row
):

    with open(
        path,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=row.keys()
        )

        writer.writerow(
            row
        )


# ============================================================
# MAIN
# ============================================================

def main():

    args = parse_args()

    dataset = args.dataset
    model_path = args.model
    input_dir = args.input_dir

    broker = args.broker
    port = args.port
    topic = args.topic
    mqtt_qos = args.mqtt_qos

    results_dir = args.results_dir
    canonical_results_dir = (
        args.canonical_results_dir
    )

    camera_id = args.camera_id
    validator_id = args.validator_id

    runs = args.runs
    warmup = args.warmup

    commit_timeout = (
        args.commit_timeout
    )

    (
        commit_events_file,
        pbft_metrics_file,
        ready_flag
    ) = build_canonical_paths(
        canonical_results_dir,
        validator_id
    )

    # --------------------------------------------------------
    # Header
    # --------------------------------------------------------

    print()
    print("=" * 80)
    print("YOLOChain — Experiment C — E2E")
    print("=" * 80)

    print()
    print("Dataset:")
    print("  ", dataset)

    print()
    print("Model:")
    print("  ", model_path)

    print()
    print("Input directory:")
    print("  ", input_dir)

    print()
    print("YOLO configuration:")
    print("  image size:", IMAGE_SIZE)
    print("  confidence:", CONF_THRESHOLD)
    print("  IoU:", IOU_THRESHOLD)
    print("  warm-up:", warmup)
    print("  runs:", runs)

    print()
    print("MQTT:")
    print("  broker:", broker)
    print("  port:", port)
    print("  topic:", topic)
    print("  QoS:", mqtt_qos)

    print()
    print("PBFT:")
    print("  N:", PBFT_N)
    print("  F:", PBFT_F)
    print("  quorum:", PBFT_QUORUM)

    print()
    print("Canonical validator:")
    print("  ", validator_id)

    print()
    print("Canonical commit events:")
    print("  ", commit_events_file)

    print()
    print("PBFT metrics:")
    print("  ", pbft_metrics_file)

    print()
    print("Network ready flag:")
    print("  ", ready_flag)

    print()
    print("Results directory:")
    print("  ", results_dir)

    print()
    print("PRIMARY E2E:")
    print(
        "  YOLO inference START"
        " -> canonical blockchain COMMIT"
    )

    print()
    print(
        "IMPORTANT: E2E is measured directly "
        "from timestamps."
    )

    print("=" * 80)

    # --------------------------------------------------------
    # Input validation
    # --------------------------------------------------------

    if not os.path.isdir(
        input_dir
    ):

        raise FileNotFoundError(
            "Input directory does not exist:\n"
            + input_dir
        )

    images = get_images(
        input_dir
    )

    if not images:

        raise RuntimeError(
            "No images found in:\n"
            + input_dir
        )

    print()
    print(
        "[DATASET] Number of images:",
        len(images)
    )

    # --------------------------------------------------------
    # Network
    # --------------------------------------------------------

    if not wait_for_network_ready(
        ready_flag,
        NETWORK_READY_TIMEOUT_SEC
    ):

        raise RuntimeError(
            "PBFT network is not ready.\n"
            "Missing:\n"
            + ready_flag
        )

    # --------------------------------------------------------
    # Commit event file
    # --------------------------------------------------------

    print()
    print(
        "[CANONICAL] Checking commit_events.csv..."
    )

    if os.path.exists(
        commit_events_file
    ):

        existing_rows = read_csv_rows(
            commit_events_file
        )

        print(
            "[CANONICAL] Existing commit events:",
            len(existing_rows)
        )

    else:

        print(
            "[CANONICAL] commit_events.csv "
            "does not exist yet."
        )

        print(
            "[CANONICAL] Waiting for validator "
            "to create it during the experiment."
        )

    # --------------------------------------------------------
    # Model
    # --------------------------------------------------------

    print()
    print(
        "[YOLO] Loading:",
        model_path
    )

    model = YOLO(
        model_path
    )

    # --------------------------------------------------------
    # Warmup
    # --------------------------------------------------------

    first_image = cv2.imread(
        images[0]
    )

    if first_image is None:

        raise RuntimeError(
            "Could not load first image:\n"
            + images[0]
        )

    print(
        "[YOLO] Warm-up:",
        warmup
    )

    for _ in range(
        warmup
    ):

        model.predict(
            first_image,
            imgsz=IMAGE_SIZE,
            conf=CONF_THRESHOLD,
            iou=IOU_THRESHOLD,
            verbose=False
        )

    # --------------------------------------------------------
    # Outputs
    # --------------------------------------------------------

    (
        frame_output,
        run_output
    ) = initialize_outputs(
        results_dir
    )

    # --------------------------------------------------------
    # MQTT
    # --------------------------------------------------------

    setup_mqtt(
        broker,
        port
    )

    # --------------------------------------------------------
    # Experiment state
    # --------------------------------------------------------

    global_sequence = 0

    all_e2e = []

    run_means = []

    run_summaries = []

    try:

        # ====================================================
        # INDEPENDENT RUNS
        # ====================================================

        for run_id in range(
            1,
            runs + 1
        ):

            print()
            print("=" * 80)
            print(
                f"RUN {run_id}/{runs}"
            )
            print("=" * 80)

            run_e2e = []

            run_yolo = []
            run_post = []
            run_json = []

            run_mqtt_call = []
            run_mqtt_completion = []

            run_pbft_preprepare = []
            run_pbft_prepare = []
            run_pbft_commit = []
            run_pbft_total = []

            frames_attempted = 0
            frames_committed = 0
            frames_failed = 0

            # ------------------------------------------------
            # Frames
            # ------------------------------------------------

            for image_index, image_path in enumerate(
                images,
                start=1
            ):

                frames_attempted += 1

                frame_id = (
                    f"run{run_id}_"
                    f"frame{image_index}"
                )

                frame_file = os.path.basename(
                    image_path
                )

                global_sequence += 1

                # ------------------------------------------------
                # Image loading excluded from timing
                # ------------------------------------------------

                image = cv2.imread(
                    image_path
                )

                if image is None:

                    frames_failed += 1

                    print(
                        "[WARN] Could not load:",
                        image_path
                    )

                    continue

                # =================================================
                # PRIMARY E2E START
                # =================================================

                yolo_start_epoch_ms = (
                    epoch_ms()
                )

                yolo_start_perf = (
                    time.perf_counter()
                )

                # =================================================
                # YOLO
                # =================================================

                predictions = model.predict(
                    image,
                    imgsz=IMAGE_SIZE,
                    conf=CONF_THRESHOLD,
                    iou=IOU_THRESHOLD,
                    verbose=False
                )

                yolo_end_perf = (
                    time.perf_counter()
                )

                yolo_inference_ms = (
                    yolo_end_perf -
                    yolo_start_perf
                ) * 1000.0

                # =================================================
                # POST-PROCESSING
                # =================================================

                post_start = (
                    time.perf_counter()
                )

                detections = extract_detections(
                    predictions[0]
                )

                post_end = (
                    time.perf_counter()
                )

                postprocessing_ms = (
                    post_end -
                    post_start
                ) * 1000.0

                # =================================================
                # JSON / TRANSACTION CREATION
                # =================================================

                json_start = (
                    time.perf_counter()
                )

                payload = create_transaction(
                    dataset=dataset,
                    camera_id=camera_id,
                    sequence=global_sequence,
                    frame_id=frame_id,
                    frame_file=frame_file,
                    image_index=image_index,
                    run_id=run_id,
                    detections=detections,
                    source_timestamp_ms=
                        yolo_start_epoch_ms
                )

                # Force serialization.
                json.dumps(
                    payload,
                    separators=(",", ":"),
                    ensure_ascii=False
                )

                json_end = (
                    time.perf_counter()
                )

                json_generation_ms = (
                    json_end -
                    json_start
                ) * 1000.0

                tx_id = payload[
                    "tx_id"
                ]

                # =================================================
                # MQTT
                # =================================================

                (
                    mqtt_publish_call_ms,
                    mqtt_publish_completion_ms
                ) = publish_transaction(
                    payload,
                    topic,
                    mqtt_qos
                )

                # =================================================
                # CANONICAL COMMIT
                # =================================================

                print(
                    f"[{run_id}:{image_index}] "
                    f"TX={tx_id} "
                    "waiting for canonical commit..."
                )

                commit_row = (
                    wait_for_canonical_commit(
                        commit_events_file,
                        tx_id,
                        commit_timeout
                    )
                )

                if commit_row is None:

                    frames_failed += 1

                    print(
                        f"[{run_id}:{image_index}] "
                        "COMMIT TIMEOUT"
                    )

                    append_csv_row(
                        frame_output,
                        {
                            "dataset":
                                dataset,

                            "run":
                                run_id,

                            "image_index":
                                image_index,

                            "frame_id":
                                frame_id,

                            "frame_file":
                                frame_file,

                            "camera_id":
                                camera_id,

                            "sequence":
                                global_sequence,

                            "tx_id":
                                tx_id,

                            "yolo_start_epoch_ms":
                                yolo_start_epoch_ms,

                            "canonical_commit_epoch_ms":
                                "",

                            "e2e_latency_ms":
                                "",

                            "yolo_inference_ms":
                                yolo_inference_ms,

                            "postprocessing_ms":
                                postprocessing_ms,

                            "json_generation_ms":
                                json_generation_ms,

                            "mqtt_publish_call_ms":
                                mqtt_publish_call_ms,

                            "mqtt_publish_completion_ms":
                                mqtt_publish_completion_ms,

                            "pbft_preprepare_ms":
                                "",

                            "pbft_prepare_ms":
                                "",

                            "pbft_commit_ms":
                                "",

                            "pbft_total_ms":
                                "",

                            "prepare_quorum":
                                "",

                            "commit_quorum":
                                "",

                            "N":
                                PBFT_N,

                            "F":
                                PBFT_F,

                            "block_index":
                                "",

                            "blockchain_length":
                                "",

                            "recovery_of":
                                "",

                            "recovery_attempt":
                                "",

                            "commit_status":
                                "TIMEOUT"
                        }
                    )

                    continue

                # =================================================
                # CANONICAL COMMIT TIMESTAMP
                # =================================================

                canonical_commit_epoch_ms = (
                    get_commit_timestamp_ms(
                        commit_row
                    )
                )

                if canonical_commit_epoch_ms is None:

                    frames_failed += 1

                    print(
                        f"[{run_id}:{image_index}] "
                        "Invalid commit_timestamp_ms"
                    )

                    continue

                # =================================================
                # PRIMARY E2E
                # =================================================

                e2e_latency_ms = (
                    canonical_commit_epoch_ms -
                    yolo_start_epoch_ms
                )

                # -------------------------------------------------
                # Clock sanity check
                # -------------------------------------------------

                if e2e_latency_ms < 0:

                    frames_failed += 1

                    print(
                        f"[{run_id}:{image_index}] "
                        f"NEGATIVE E2E = "
                        f"{e2e_latency_ms:.6f} ms"
                    )

                    continue

                # =================================================
                # PBFT METRICS
                # =================================================

                pbft = extract_pbft_metrics(
                    pbft_metrics_file,
                    tx_id
                )

                # =================================================
                # RECORD FRAME
                # =================================================

                frame_row = {

                    "dataset":
                        dataset,

                    "run":
                        run_id,

                    "image_index":
                        image_index,

                    "frame_id":
                        frame_id,

                    "frame_file":
                        frame_file,

                    "camera_id":
                        camera_id,

                    "sequence":
                        global_sequence,

                    "tx_id":
                        tx_id,

                    "yolo_start_epoch_ms":
                        yolo_start_epoch_ms,

                    "canonical_commit_epoch_ms":
                        canonical_commit_epoch_ms,

                    "e2e_latency_ms":
                        e2e_latency_ms,

                    "yolo_inference_ms":
                        yolo_inference_ms,

                    "postprocessing_ms":
                        postprocessing_ms,

                    "json_generation_ms":
                        json_generation_ms,

                    "mqtt_publish_call_ms":
                        mqtt_publish_call_ms,

                    "mqtt_publish_completion_ms":
                        mqtt_publish_completion_ms,

                    "pbft_preprepare_ms":
                        pbft[
                            "pbft_preprepare_ms"
                        ],

                    "pbft_prepare_ms":
                        pbft[
                            "pbft_prepare_ms"
                        ],

                    "pbft_commit_ms":
                        pbft[
                            "pbft_commit_ms"
                        ],

                    "pbft_total_ms":
                        pbft[
                            "pbft_total_ms"
                        ],

                    "prepare_quorum":
                        pbft[
                            "prepare_quorum"
                        ],

                    "commit_quorum":
                        pbft[
                            "commit_quorum"
                        ],

                    "N":
                        pbft["N"]
                        or PBFT_N,

                    "F":
                        pbft["F"]
                        or PBFT_F,

                    "block_index":
                        pbft["block_index"]
                        or commit_row.get(
                            "block_index"
                        ),

                    "blockchain_length":
                        pbft[
                            "blockchain_length"
                        ]
                        or commit_row.get(
                            "blockchain_length"
                        ),

                    "recovery_of":
                        pbft["recovery_of"]
                        or commit_row.get(
                            "recovery_of"
                        ),

                    "recovery_attempt":
                        pbft[
                            "recovery_attempt"
                        ]
                        or commit_row.get(
                            "recovery_attempt"
                        ),

                    "commit_status":
                        "COMMITTED"
                }

                append_csv_row(
                    frame_output,
                    frame_row
                )

                # =================================================
                # AGGREGATION
                # =================================================

                frames_committed += 1

                run_e2e.append(
                    e2e_latency_ms
                )

                all_e2e.append(
                    e2e_latency_ms
                )

                run_yolo.append(
                    yolo_inference_ms
                )

                run_post.append(
                    postprocessing_ms
                )

                run_json.append(
                    json_generation_ms
                )

                run_mqtt_call.append(
                    mqtt_publish_call_ms
                )

                if (
                    mqtt_publish_completion_ms
                    is not None
                ):

                    run_mqtt_completion.append(
                        mqtt_publish_completion_ms
                    )

                if (
                    pbft[
                        "pbft_preprepare_ms"
                    ]
                    is not None
                ):

                    run_pbft_preprepare.append(
                        pbft[
                            "pbft_preprepare_ms"
                        ]
                    )

                if (
                    pbft[
                        "pbft_prepare_ms"
                    ]
                    is not None
                ):

                    run_pbft_prepare.append(
                        pbft[
                            "pbft_prepare_ms"
                        ]
                    )

                if (
                    pbft[
                        "pbft_commit_ms"
                    ]
                    is not None
                ):

                    run_pbft_commit.append(
                        pbft[
                            "pbft_commit_ms"
                        ]
                    )

                if (
                    pbft[
                        "pbft_total_ms"
                    ]
                    is not None
                ):

                    run_pbft_total.append(
                        pbft[
                            "pbft_total_ms"
                        ]
                    )

                # =================================================
                # PROGRESS
                # =================================================

                mqtt_display = (
                    mqtt_publish_completion_ms
                    if mqtt_publish_completion_ms
                    is not None
                    else float("nan")
                )

                pbft_display = (
                    pbft[
                        "pbft_total_ms"
                    ]
                    if pbft[
                        "pbft_total_ms"
                    ] is not None
                    else float("nan")
                )

                print(
                    f"[{run_id}:{image_index}] "
                    f"E2E={e2e_latency_ms:.3f} ms "
                    f"YOLO={yolo_inference_ms:.3f} ms "
                    f"MQTT={mqtt_display:.3f} ms "
                    f"PBFT={pbft_display:.3f} ms"
                )

            # ====================================================
            # RUN STATISTICS
            # ====================================================

            run_mean_e2e = mean(
                run_e2e
            )

            run_sd_e2e = sd(
                run_e2e
            )

            run_p95_e2e = percentile(
                run_e2e,
                95
            )

            run_p99_e2e = percentile(
                run_e2e,
                99
            )

            run_fps = equivalent_fps(
                run_mean_e2e
            )

            run_summary = {

                "dataset":
                    dataset,

                "run":
                    run_id,

                "frames_attempted":
                    frames_attempted,

                "frames_committed":
                    frames_committed,

                "frames_failed":
                    frames_failed,

                "e2e_mean_ms":
                    run_mean_e2e,

                "e2e_sd_ms":
                    run_sd_e2e,

                "e2e_p95_ms":
                    run_p95_e2e,

                "e2e_p99_ms":
                    run_p99_e2e,

                "equivalent_fps":
                    run_fps,

                "yolo_mean_ms":
                    mean(run_yolo),

                "postprocessing_mean_ms":
                    mean(run_post),

                "json_generation_mean_ms":
                    mean(run_json),

                "mqtt_publish_call_mean_ms":
                    mean(run_mqtt_call),

                "mqtt_publish_completion_mean_ms":
                    mean(run_mqtt_completion),

                "pbft_preprepare_mean_ms":
                    mean(run_pbft_preprepare),

                "pbft_prepare_mean_ms":
                    mean(run_pbft_prepare),

                "pbft_commit_mean_ms":
                    mean(run_pbft_commit),

                "pbft_total_mean_ms":
                    mean(run_pbft_total)
            }

            append_csv_row(
                run_output,
                run_summary
            )

            run_means.append(
                run_mean_e2e
            )

            run_summaries.append(
                run_summary
            )

            print()
            print(
                f"RUN {run_id} SUMMARY"
            )

            print(
                "  Frames attempted:",
                frames_attempted
            )

            print(
                "  Frames committed:",
                frames_committed
            )

            print(
                "  Frames failed:",
                frames_failed
            )

            print(
                f"  E2E mean: "
                f"{run_mean_e2e:.6f} ms"
            )

            print(
                f"  E2E SD: "
                f"{run_sd_e2e:.6f} ms"
            )

            print(
                f"  E2E P95: "
                f"{run_p95_e2e:.6f} ms"
            )

            print(
                f"  E2E P99: "
                f"{run_p99_e2e:.6f} ms"
            )

            print(
                f"  Equivalent FPS: "
                f"{run_fps:.6f}"
            )

    finally:

        shutdown_mqtt()

    # ========================================================
    # FINAL STATISTICS
    # ========================================================

    overall_mean = mean(
        all_e2e
    )

    sd_across_runs = sd(
        run_means
    )

    ci_low, ci_high = ci95_t(
        run_means
    )

    pooled_p95 = percentile(
        all_e2e,
        95
    )

    pooled_p99 = percentile(
        all_e2e,
        99
    )

    fps = equivalent_fps(
        overall_mean
    )

    total_attempted = sum(
        x["frames_attempted"]
        for x in run_summaries
    )

    total_committed = sum(
        x["frames_committed"]
        for x in run_summaries
    )

    total_failed = sum(
        x["frames_failed"]
        for x in run_summaries
    )

    # ========================================================
    # FINAL JSON
    # ========================================================

    final_json = {

        "experiment":
            "C",

        "dataset":
            dataset,

        "architecture":
            "YOLOv8+MQTT+P2P+PBFT-style+local-blockchain",

        "security":

            {
                "pqc":
                    False,

                "kem":
                    False,

                "aes":
                    False,

                "signature":
                    False
            },

        "yolo":

            {
                "model":
                    model_path,

                "image_size":
                    IMAGE_SIZE,

                "confidence":
                    CONF_THRESHOLD,

                "iou":
                    IOU_THRESHOLD,

                "warmup":
                    warmup,

                "runs":
                    runs
            },

        "mqtt":

            {
                "broker":
                    broker,

                "port":
                    port,

                "topic":
                    topic,

                "qos":
                    mqtt_qos,

                "retain":
                    False
            },

        "pbft":

            {
                "N":
                    PBFT_N,

                "F":
                    PBFT_F,

                "quorum":
                    PBFT_QUORUM,

                "canonical_validator":
                    validator_id
            },

        "e2e_definition":
            "YOLO inference START -> "
            "canonical blockchain COMMIT",

        "canonical_commit_source":
            commit_events_file,

        "pbft_metrics_source":
            pbft_metrics_file,

        "frames":

            {
                "attempted":
                    total_attempted,

                "committed":
                    total_committed,

                "failed":
                    total_failed
            },

        "statistics":

            {
                "successful_committed_frames":
                    len(all_e2e),

                "run_means_ms":
                    run_means,

                "mean_e2e_ms":
                    overall_mean,

                "sd_across_independent_run_means_ms":
                    sd_across_runs,

                "ci95_low_ms":
                    ci_low,

                "ci95_high_ms":
                    ci_high,

                "pooled_p95_ms":
                    pooled_p95,

                "pooled_p99_ms":
                    pooled_p99,

                "latency_derived_equivalent_fps":
                    fps
            },

        "run_summaries":
            run_summaries,

        "generated_utc":
            utc_now_iso()
    }

    final_json_file = os.path.join(
        results_dir,
        "C_E2E_FINAL.json"
    )

    with open(
        final_json_file,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            final_json,
            f,
            indent=2
        )

    # ========================================================
    # FINAL CONSOLE OUTPUT
    # ========================================================

    print()
    print("=" * 80)
    print("FINAL EXPERIMENT C — E2E RESULTS")
    print("=" * 80)

    print()
    print(
        "Committed frames:",
        len(all_e2e)
    )

    print(
        f"Mean E2E latency: "
        f"{overall_mean:.6f} ms"
    )

    print(
        f"SD across run means: "
        f"{sd_across_runs:.6f} ms"
    )

    print(
        f"95% CI: "
        f"{ci_low:.6f} – "
        f"{ci_high:.6f} ms"
    )

    print(
        f"P95 pooled: "
        f"{pooled_p95:.6f} ms"
    )

    print(
        f"P99 pooled: "
        f"{pooled_p99:.6f} ms"
    )

    print(
        f"Latency-derived equivalent FPS: "
        f"{fps:.6f}"
    )

    print()
    print(
        "Attempted:",
        total_attempted
    )

    print(
        "Committed:",
        total_committed
    )

    print(
        "Failed:",
        total_failed
    )

    print()
    print(
        "Frame-level results:"
    )

    print(
        " ",
        frame_output
    )

    print()
    print(
        "Run summary:"
    )

    print(
        " ",
        run_output
    )

    print()
    print(
        "Final JSON:"
    )

    print(
        " ",
        final_json_file
    )

    print()
    print("=" * 80)
    print("DONE")
    print("=" * 80)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except KeyboardInterrupt:

        shutdown_mqtt()

        print()
        print(
            "[C] Experiment interrupted."
        )

        sys.exit(130)

    except Exception as e:

        shutdown_mqtt()

        print()
        print("=" * 80)
        print("[C] FATAL ERROR")
        print("=" * 80)

        print(
            type(e).__name__ + ":",
            str(e)
        )

        sys.exit(1)
