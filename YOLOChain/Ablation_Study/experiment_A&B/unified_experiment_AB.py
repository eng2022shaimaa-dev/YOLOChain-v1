#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
YOLOChain
Unified Experiment A/B

Experiment A:
    YOLOv8 only

Experiment B:
    YOLOv8 + MQTT

Supported datasets:
    COCO128
    MOT17-04-SDP

Main measurements:
    - YOLO preprocess
    - YOLO inference
    - YOLO post-processing
    - Box extraction
    - End-to-end latency
    - P95 / P99
    - Equivalent FPS
    - MQTT delivery latency (B)
    - Mean / SD / 95% CI across 5 runs
    - Precision
    - Recall
    - F1
    - mAP@0.5
    - mAP@0.5:0.95
    - TP / FP / FN for MOT
    - MOT Precision / Recall / F1

Important timing rules:
    - Image loading is excluded.
    - Ground-truth loading/matching is excluded from latency.
    - Accuracy calculation is excluded from latency.
    - A and B use the same YOLO timing boundary.
    - B E2E includes the added MQTT path.
    - MQTT delivery latency is measured separately.
    - A->B E2E difference is NOT treated as pure MQTT latency.
    - Box extraction measures ONLY extraction of xyxy boxes from
      the Ultralytics Results object.
    - E2E is measured directly using wall-clock elapsed time and
      is NOT calculated by summing component timings.

Memory-safety:
    - MOT frames are processed one at a time.
    - Ultralytics Results objects are released immediately.
    - Raw frame-level arrays contain only scalar measurements.
    - Garbage collection is periodically triggered outside timing.
    - Accuracy validation is performed after runtime measurements.
"""

import os
import gc
import csv
import json
import time
import math
import argparse
from pathlib import Path
from collections import defaultdict

import cv2
import numpy as np
import torch

from ultralytics import YOLO


# ============================================================
# CONSTANTS
# ============================================================

T_CRITICAL_DF4 = 2.7764451052

DEFAULT_MODEL = "yolov8n.pt"

DEFAULT_IMG_SIZE = 416
DEFAULT_CONF = 0.25
DEFAULT_IOU = 0.50

DEFAULT_RUNS = 5
DEFAULT_WARMUP = 10

MOT_IOU_MATCH = 0.50

DEFAULT_MQTT_HOST = "127.0.0.1"
DEFAULT_MQTT_PORT = 1883
DEFAULT_MQTT_TOPIC = "pqc/yolo/video"
DEFAULT_MQTT_QOS = 0
DEFAULT_MQTT_RETAIN = False

SUPPORTED_IMAGE_EXTENSIONS = {
    ".jpg",
    ".jpeg",
    ".png",
    ".bmp",
    ".tif",
    ".tiff",
}


# ============================================================
# GENERAL HELPERS
# ============================================================

def ensure_dir(path):
    Path(path).mkdir(parents=True, exist_ok=True)


def safe_float(x):
    try:
        value = float(x)

        if np.isfinite(value):
            return value

        return 0.0

    except Exception:
        return 0.0


def mean_or_nan(values):
    if not values:
        return float("nan")

    return float(np.mean(values))


def sd_or_nan(values):
    if len(values) < 2:
        return float("nan")

    return float(np.std(values, ddof=1))


def ci95(values):
    """
    95% CI for run-level means.

    For 5 independent runs:
        df = 4
        t = 2.7764451052
    """

    n = len(values)

    if n < 2:
        return float("nan"), float("nan")

    m = mean_or_nan(values)
    sd = sd_or_nan(values)

    if not np.isfinite(sd):
        return float("nan"), float("nan")

    margin = T_CRITICAL_DF4 * sd / math.sqrt(n)

    return (
        float(m - margin),
        float(m + margin),
    )


def equivalent_fps(mean_ms):
    if not np.isfinite(mean_ms):
        return float("nan")

    if mean_ms <= 0:
        return float("nan")

    return 1000.0 / mean_ms


def percentile(values, p):
    if not values:
        return float("nan")

    return float(
        np.percentile(
            np.asarray(
                values,
                dtype=np.float64,
            ),
            p,
        )
    )


def release_memory():
    """
    Called outside the measured timing interval.
    """

    gc.collect()

    if torch.cuda.is_available():

        try:
            torch.cuda.empty_cache()

        except Exception:
            pass


def save_json(path, data):

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:

        json.dump(
            data,
            f,
            indent=2,
        )


def write_csv(
    path,
    rows,
    fieldnames,
):

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()

        writer.writerows(rows)


def print_separator(
    char="=",
    n=90,
):

    print(char * n)


# ============================================================
# IMAGE DISCOVERY
# ============================================================

def find_images(directory):

    directory = Path(directory)

    if not directory.exists():

        raise FileNotFoundError(
            f"Directory not found: {directory}"
        )

    paths = [
        p
        for p in directory.iterdir()
        if (
            p.is_file()
            and p.suffix.lower()
            in SUPPORTED_IMAGE_EXTENSIONS
        )
    ]

    return sorted(paths)


# ============================================================
# MQTT
# ============================================================

class MQTTReceiver:

    def __init__(
        self,
        host,
        port,
        topic,
    ):

        self.host = host
        self.port = port
        self.topic = topic

        self.client = None
        self.available = False

        self.last_message_id = None
        self.last_receive_time = None

        try:

            import paho.mqtt.client as mqtt

            self.mqtt = mqtt

            self.client = mqtt.Client()

            self.client.on_message = (
                self._on_message
            )

            self.client.connect(
                self.host,
                self.port,
                keepalive=60,
            )

            self.client.subscribe(
                self.topic
            )

            self.client.loop_start()

            self.available = True

            print(
                f"[MQTT] Receiver connected to "
                f"{self.host}:{self.port}, "
                f"topic={self.topic}"
            )

        except Exception as e:

            print(
                "[MQTT] Receiver ERROR:",
                repr(e),
            )

            print(
                "[MQTT] Experiment B requires "
                "a running MQTT broker."
            )

            raise

    def _on_message(
        self,
        client,
        userdata,
        msg,
    ):

        try:

            payload = json.loads(
                msg.payload.decode(
                    "utf-8"
                )
            )

            message_id = payload.get(
                "message_id"
            )

            if message_id is not None:

                self.last_message_id = (
                    message_id
                )

                self.last_receive_time = (
                    time.perf_counter()
                )

        except Exception:

            pass

    def wait_for_message(
        self,
        message_id,
        timeout=5.0,
    ):

        deadline = (
            time.perf_counter()
            + timeout
        )

        while (
            time.perf_counter()
            < deadline
        ):

            if (
                self.last_message_id
                == message_id
            ):

                t = (
                    self.last_receive_time
                )

                self.last_message_id = None
                self.last_receive_time = None

                return t

            time.sleep(0.0001)

        return None

    def close(self):

        if self.client is not None:

            try:
                self.client.loop_stop()

            except Exception:
                pass

            try:
                self.client.disconnect()

            except Exception:
                pass


class MQTTPublisher:

    def __init__(
        self,
        host,
        port,
        topic,
        qos=0,
        retain=False,
    ):

        import paho.mqtt.client as mqtt

        self.host = host
        self.port = port
        self.topic = topic
        self.qos = qos
        self.retain = retain

        self.client = mqtt.Client()

        self.client.connect(
            self.host,
            self.port,
            keepalive=60,
        )

        self.client.loop_start()

    def publish(self, payload):

        info = self.client.publish(
            self.topic,
            json.dumps(payload),
            qos=self.qos,
            retain=self.retain,
        )

        return info

    def close(self):

        try:
            self.client.loop_stop()

        except Exception:
            pass

        try:
            self.client.disconnect()

        except Exception:
            pass


# ============================================================
# YOLO MODEL
# ============================================================

def load_model(model_path):

    print(
        f"[MODEL] Loading: {model_path}"
    )

    model = YOLO(model_path)

    print("[MODEL] Loaded.")

    return model


def predict_one(
    model,
    frame,
    img_size,
    conf,
    iou,
    classes=None,
):
    """
    Run YOLO and separately measure:

        1. Ultralytics preprocess
        2. Ultralytics inference
        3. Ultralytics postprocess
        4. Box extraction

    IMPORTANT:

    box_extraction_ms measures ONLY:

        result.boxes.xyxy
        detach()
        cpu()
        numpy()
        iteration over boxes

    It does NOT measure the entire YOLO execution.
    """

    results = model.predict(
        source=frame,
        imgsz=img_size,
        conf=conf,
        iou=iou,
        classes=classes,
        device="cpu",
        verbose=False,
        stream=False,
        save=False,
        show=False,
    )

    result = results[0]

    speed = (
        getattr(
            result,
            "speed",
            {},
        )
        or {}
    )

    preprocess_ms = safe_float(
        speed.get(
            "preprocess",
            0.0,
        )
    )

    inference_ms = safe_float(
        speed.get(
            "inference",
            0.0,
        )
    )

    postprocess_ms = safe_float(
        speed.get(
            "postprocess",
            0.0,
        )
    )

    # ========================================================
    # BOX EXTRACTION ONLY
    # ========================================================

    t_extract_start = (
        time.perf_counter()
    )

    boxes = []

    if result.boxes is not None:

        xyxy = result.boxes.xyxy

        if xyxy is not None:

            xyxy = (
                xyxy
                .detach()
                .cpu()
                .numpy()
            )

            for b in xyxy:

                boxes.append(
                    (
                        float(b[0]),
                        float(b[1]),
                        float(b[2]),
                        float(b[3]),
                    )
                )

            del xyxy

    t_extract_end = (
        time.perf_counter()
    )

    box_extraction_ms = (
        t_extract_end
        - t_extract_start
    ) * 1000.0

    # ========================================================
    # RELEASE ULTRALYTICS RESULTS
    # ========================================================

    del result
    del results

    return (
        boxes,
        preprocess_ms,
        inference_ms,
        postprocess_ms,
        box_extraction_ms,
    )


# ============================================================
# MOT GROUND TRUTH
# ============================================================

def load_mot_gt(gt_file):

    gt = defaultdict(list)

    with open(
        gt_file,
        "r",
        encoding="utf-8",
    ) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            parts = line.split(",")

            if len(parts) < 6:
                continue

            frame_id = int(
                float(parts[0])
            )

            x = float(parts[2])
            y = float(parts[3])
            w = float(parts[4])
            h = float(parts[5])

            # MOT17 pedestrian boxes.
            # Ignore invalid/ignored regions
            # if confidence is zero.

            if len(parts) >= 7:

                try:

                    conf = float(
                        parts[6]
                    )

                    if conf <= 0:
                        continue

                except Exception:

                    pass

            gt_box = (
                x,
                y,
                x + w,
                y + h,
            )

            gt[frame_id].append(
                gt_box
            )

    return gt


# ============================================================
# IOU
# ============================================================

def box_iou(a, b):

    ax1, ay1, ax2, ay2 = a
    bx1, by1, bx2, by2 = b

    ix1 = max(
        ax1,
        bx1,
    )

    iy1 = max(
        ay1,
        by1,
    )

    ix2 = min(
        ax2,
        bx2,
    )

    iy2 = min(
        ay2,
        by2,
    )

    iw = max(
        0.0,
        ix2 - ix1,
    )

    ih = max(
        0.0,
        iy2 - iy1,
    )

    intersection = (
        iw * ih
    )

    area_a = (
        max(
            0.0,
            ax2 - ax1,
        )
        *
        max(
            0.0,
            ay2 - ay1,
        )
    )

    area_b = (
        max(
            0.0,
            bx2 - bx1,
        )
        *
        max(
            0.0,
            by2 - by1,
        )
    )

    union = (
        area_a
        + area_b
        - intersection
    )

    if union <= 0:
        return 0.0

    return (
        intersection / union
    )


# ============================================================
# GREEDY MOT MATCHING
# ============================================================

def greedy_match(
    pred_boxes,
    gt_boxes,
    threshold=0.50,
):

    if (
        not pred_boxes
        and not gt_boxes
    ):
        return 0, 0, 0

    if not pred_boxes:

        return (
            0,
            0,
            len(gt_boxes),
        )

    if not gt_boxes:

        return (
            0,
            len(pred_boxes),
            0,
        )

    pairs = []

    for pi, pred in enumerate(
        pred_boxes
    ):

        for gi, gt in enumerate(
            gt_boxes
        ):

            iou = box_iou(
                pred,
                gt,
            )

            if iou >= threshold:

                pairs.append(
                    (
                        iou,
                        pi,
                        gi,
                    )
                )

    pairs.sort(
        reverse=True
    )

    used_pred = set()
    used_gt = set()

    tp = 0

    for (
        iou,
        pi,
        gi,
    ) in pairs:

        if pi in used_pred:
            continue

        if gi in used_gt:
            continue

        used_pred.add(pi)
        used_gt.add(gi)

        tp += 1

    fp = (
        len(pred_boxes)
        - tp
    )

    fn = (
        len(gt_boxes)
        - tp
    )

    return (
        tp,
        fp,
        fn,
    )


def metrics_from_counts(
    tp,
    fp,
    fn,
):

    precision = (
        tp / (tp + fp)
        if (tp + fp) > 0
        else 0.0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn) > 0
        else 0.0
    )

    f1 = (
        2.0
        * precision
        * recall
        / (precision + recall)
        if (
            precision + recall
        ) > 0
        else 0.0
    )

    return (
        precision,
        recall,
        f1,
    )


# ============================================================
# WARMUP
# ============================================================

def warmup_images(
    model,
    image_paths,
    img_size,
    conf,
    iou,
    classes,
    warmup,
):

    n = min(
        warmup,
        len(image_paths),
    )

    print(
        f"[WARMUP] {n} frames"
    )

    for i in range(n):

        frame = cv2.imread(
            str(image_paths[i])
        )

        if frame is None:
            continue

        try:

            predict_one(
                model,
                frame,
                img_size,
                conf,
                iou,
                classes,
            )

        finally:

            del frame

        if (
            (i + 1) % 5
            == 0
        ):

            release_memory()

    release_memory()


# ============================================================
# PROCESS ONE FRAME
# ============================================================

def process_frame(
    model,
    frame,
    experiment,
    img_size,
    conf,
    iou,
    classes,
    mqtt_publisher=None,
    mqtt_receiver=None,
    message_id=None,
    mqtt_timeout=5.0,
    camera_id="camera_01",
    frame_number=0,
):
    """
    Timing definition:

    Experiment A:

        E2E starts immediately before model.predict()
        and ends immediately after box extraction.

    Experiment B:

        E2E starts immediately before model.predict()
        and ends at MQTT message reception.

    Image loading is outside this interval.

    GT matching is outside this interval.

    Accuracy calculation is outside this interval.

    E2E is measured directly and is NOT calculated
    by summing preprocess + inference + postprocess
    + extraction + MQTT.
    """

    # ========================================================
    # START E2E
    # ========================================================

    t_e2e_start = (
        time.perf_counter()
    )

    (
        boxes,
        preprocess_ms,
        inference_ms,
        postprocess_ms,
        box_extraction_ms,
    ) = predict_one(
        model=model,
        frame=frame,
        img_size=img_size,
        conf=conf,
        iou=iou,
        classes=classes,
    )

    # ========================================================
    # YOLO / BOX EXTRACTION FINISHED
    # ========================================================

    t_after_yolo = (
        time.perf_counter()
    )

    mqtt_delivery_ms = None

    # ========================================================
    # EXPERIMENT B — MQTT
    # ========================================================

    if experiment == "B":

        payload = {
            "message_id": message_id,
            "camera_id": camera_id,
            "frame_number": frame_number,
            "timestamp": time.time(),

            "detections": [
                {
                    "x1": b[0],
                    "y1": b[1],
                    "x2": b[2],
                    "y2": b[3],
                }
                for b in boxes
            ],
        }

        # ----------------------------------------------------
        # MQTT component timer
        # ----------------------------------------------------

        mqtt_publish_start = (
            time.perf_counter()
        )

        mqtt_publisher.publish(
            payload
        )

        receive_time = (
            mqtt_receiver.wait_for_message(
                message_id,
                timeout=mqtt_timeout,
            )
        )

        if receive_time is None:

            raise RuntimeError(
                "MQTT timeout for "
                f"message {message_id}"
            )

        mqtt_delivery_ms = (
            receive_time
            - mqtt_publish_start
        ) * 1000.0

        # ----------------------------------------------------
        # B E2E ends at MQTT reception.
        # ----------------------------------------------------

        t_e2e_end = receive_time

    else:

        # ----------------------------------------------------
        # A E2E ends after YOLO + box extraction.
        # ----------------------------------------------------

        t_e2e_end = (
            t_after_yolo
        )

    # ========================================================
    # DIRECT E2E
    # ========================================================

    e2e_ms = (
        t_e2e_end
        - t_e2e_start
    ) * 1000.0

    return {

        "e2e_ms": float(
            e2e_ms
        ),

        "preprocess_ms": float(
            preprocess_ms
        ),

        "inference_ms": float(
            inference_ms
        ),

        "postprocess_ms": float(
            postprocess_ms
        ),

        "box_extraction_ms": float(
            box_extraction_ms
        ),

        "mqtt_delivery_ms": (
            float(
                mqtt_delivery_ms
            )
            if mqtt_delivery_ms
            is not None
            else None
        ),

        "num_detections": len(
            boxes
        ),

        "boxes": boxes,
    }


# ============================================================
# RUN COCO RUNTIME
# ============================================================

def run_coco_runtime(
    model,
    image_paths,
    experiment,
    img_size,
    conf,
    iou,
    classes,
    runs,
    warmup,
    mqtt_publisher=None,
    mqtt_receiver=None,
    mqtt_timeout=5.0,
):

    all_rows = []
    run_summaries = []

    # ========================================================
    # WARMUP
    # ========================================================

    warmup_images(
        model,
        image_paths,
        img_size,
        conf,
        iou,
        classes,
        warmup,
    )

    # ========================================================
    # RUNS
    # ========================================================

    for run_idx in range(
        1,
        runs + 1,
    ):

        print_separator()

        print(
            f"COCO {experiment} "
            f"— RUN {run_idx}/{runs}"
        )

        print_separator()

        e2e_values = []
        preprocess_values = []
        inference_values = []
        postprocess_values = []
        extraction_values = []
        mqtt_values = []

        for (
            frame_idx,
            image_path,
        ) in enumerate(
            image_paths,
            start=1,
        ):

            # ------------------------------------------------
            # Image loading OUTSIDE timing.
            # ------------------------------------------------

            frame = cv2.imread(
                str(image_path)
            )

            if frame is None:

                print(
                    "[WARNING] Could not read "
                    f"{image_path}"
                )

                continue

            message_id = (
                f"{experiment}-"
                f"run{run_idx}-"
                f"frame{frame_idx}-"
                f"{time.time_ns()}"
            )

            try:

                result = process_frame(
                    model=model,
                    frame=frame,
                    experiment=experiment,
                    img_size=img_size,
                    conf=conf,
                    iou=iou,
                    classes=classes,
                    mqtt_publisher=mqtt_publisher,
                    mqtt_receiver=mqtt_receiver,
                    message_id=message_id,
                    mqtt_timeout=mqtt_timeout,
                    camera_id="camera_COCO128",
                    frame_number=frame_idx,
                )

                row = {

                    "experiment": experiment,
                    "dataset": "COCO128",
                    "run": run_idx,
                    "frame": frame_idx,
                    "image": image_path.name,

                    "e2e_ms": result[
                        "e2e_ms"
                    ],

                    "preprocess_ms": result[
                        "preprocess_ms"
                    ],

                    "inference_ms": result[
                        "inference_ms"
                    ],

                    "postprocess_ms": result[
                        "postprocess_ms"
                    ],

                    "box_extraction_ms": result[
                        "box_extraction_ms"
                    ],

                    "mqtt_delivery_ms": result[
                        "mqtt_delivery_ms"
                    ],

                    "num_detections": result[
                        "num_detections"
                    ],
                }

                all_rows.append(
                    row
                )

                e2e_values.append(
                    result["e2e_ms"]
                )

                preprocess_values.append(
                    result[
                        "preprocess_ms"
                    ]
                )

                inference_values.append(
                    result[
                        "inference_ms"
                    ]
                )

                postprocess_values.append(
                    result[
                        "postprocess_ms"
                    ]
                )

                extraction_values.append(
                    result[
                        "box_extraction_ms"
                    ]
                )

                if (
                    result[
                        "mqtt_delivery_ms"
                    ]
                    is not None
                ):

                    mqtt_values.append(
                        result[
                            "mqtt_delivery_ms"
                        ]
                    )

            finally:

                del frame

            if (
                frame_idx % 25
                == 0
            ):

                release_memory()

        # ====================================================
        # RUN SUMMARY
        # ====================================================

        run_summary = {

            "run": run_idx,

            "frames": len(
                e2e_values
            ),

            "e2e_mean_ms":
                mean_or_nan(
                    e2e_values
                ),

            "e2e_sd_ms":
                sd_or_nan(
                    e2e_values
                ),

            "e2e_p95_ms":
                percentile(
                    e2e_values,
                    95,
                ),

            "e2e_p99_ms":
                percentile(
                    e2e_values,
                    99,
                ),

            "e2e_median_ms":
                percentile(
                    e2e_values,
                    50,
                ),

            "equivalent_fps":
                equivalent_fps(
                    mean_or_nan(
                        e2e_values
                    )
                ),

            "preprocess_mean_ms":
                mean_or_nan(
                    preprocess_values
                ),

            "preprocess_sd_ms":
                sd_or_nan(
                    preprocess_values
                ),

            "inference_mean_ms":
                mean_or_nan(
                    inference_values
                ),

            "inference_sd_ms":
                sd_or_nan(
                    inference_values
                ),

            "postprocess_mean_ms":
                mean_or_nan(
                    postprocess_values
                ),

            "postprocess_sd_ms":
                sd_or_nan(
                    postprocess_values
                ),

            "box_extraction_mean_ms":
                mean_or_nan(
                    extraction_values
                ),

            "box_extraction_sd_ms":
                sd_or_nan(
                    extraction_values
                ),

            "mqtt_delivery_mean_ms":
                (
                    mean_or_nan(
                        mqtt_values
                    )
                    if mqtt_values
                    else None
                ),

            "mqtt_delivery_sd_ms":
                (
                    sd_or_nan(
                        mqtt_values
                    )
                    if mqtt_values
                    else None
                ),
        }

        run_summaries.append(
            run_summary
        )

        # ====================================================
        # PRINT RUN
        # ====================================================

        print(
            f"Mean E2E: "
            f"{run_summary['e2e_mean_ms']:.6f} ms"
        )

        print(
            f"SD: "
            f"{run_summary['e2e_sd_ms']:.6f} ms"
        )

        print(
            f"P95: "
            f"{run_summary['e2e_p95_ms']:.6f} ms"
        )

        print(
            f"P99: "
            f"{run_summary['e2e_p99_ms']:.6f} ms"
        )

        print(
            f"FPS: "
            f"{run_summary['equivalent_fps']:.6f}"
        )

        print(
            f"YOLO preprocess: "
            f"{run_summary['preprocess_mean_ms']:.6f} ms"
        )

        print(
            f"YOLO inference: "
            f"{run_summary['inference_mean_ms']:.6f} ms"
        )

        print(
            f"YOLO postprocess: "
            f"{run_summary['postprocess_mean_ms']:.6f} ms"
        )

        print(
            f"Box extraction: "
            f"{run_summary['box_extraction_mean_ms']:.6f} ms"
        )

        if mqtt_values:

            print(
                f"MQTT delivery: "
                f"{run_summary['mqtt_delivery_mean_ms']:.6f} ms"
            )

        release_memory()

    return (
        all_rows,
        run_summaries,
    )


# ============================================================
# RUN MOT RUNTIME
# ============================================================

def run_mot_runtime(
    model,
    frame_paths,
    gt,
    experiment,
    img_size,
    conf,
    iou,
    classes,
    runs,
    warmup,
    mqtt_publisher=None,
    mqtt_receiver=None,
    mqtt_timeout=5.0,
):

    all_rows = []
    run_summaries = []

    # ========================================================
    # WARMUP
    # ========================================================

    warmup_count = min(
        warmup,
        len(frame_paths),
    )

    print(
        f"[WARMUP] MOT frames: "
        f"{warmup_count}"
    )

    for i in range(
        warmup_count
    ):

        frame = cv2.imread(
            str(frame_paths[i])
        )

        if frame is None:
            continue

        try:

            predict_one(
                model,
                frame,
                img_size,
                conf,
                iou,
                classes,
            )

        finally:

            del frame

        if (
            (i + 1) % 5
            == 0
        ):

            release_memory()

    release_memory()

    # ========================================================
    # ACTUAL RUNS
    # ========================================================

    for run_idx in range(
        1,
        runs + 1,
    ):

        print_separator()

        print(
            f"MOT17-04-SDP "
            f"{experiment} — "
            f"RUN {run_idx}/{runs}"
        )

        print_separator()

        e2e_values = []
        preprocess_values = []
        inference_values = []
        postprocess_values = []
        extraction_values = []
        mqtt_values = []

        tp_total = 0
        fp_total = 0
        fn_total = 0

        for (
            frame_idx,
            frame_path,
        ) in enumerate(
            frame_paths,
            start=1,
        ):

            # ------------------------------------------------
            # Image loading OUTSIDE timing.
            # ------------------------------------------------

            frame = cv2.imread(
                str(frame_path)
            )

            if frame is None:

                print(
                    "[WARNING] Could not read "
                    f"{frame_path}"
                )

                continue

            message_id = (
                f"{experiment}-"
                f"run{run_idx}-"
                f"frame{frame_idx}-"
                f"{time.time_ns()}"
            )

            try:

                result = process_frame(
                    model=model,
                    frame=frame,
                    experiment=experiment,
                    img_size=img_size,
                    conf=conf,
                    iou=iou,
                    classes=classes,
                    mqtt_publisher=mqtt_publisher,
                    mqtt_receiver=mqtt_receiver,
                    message_id=message_id,
                    mqtt_timeout=mqtt_timeout,
                    camera_id=(
                        "camera_MOT17_04_SDP"
                    ),
                    frame_number=frame_idx,
                )

                pred_boxes = result[
                    "boxes"
                ]

                # ------------------------------------------------
                # GT access/matching AFTER E2E timing.
                # ------------------------------------------------

                gt_boxes = gt.get(
                    frame_idx,
                    [],
                )

                tp, fp, fn = (
                    greedy_match(
                        pred_boxes,
                        gt_boxes,
                        threshold=MOT_IOU_MATCH,
                    )
                )

                tp_total += tp
                fp_total += fp
                fn_total += fn

                row = {

                    "experiment": experiment,
                    "dataset": (
                        "MOT17-04-SDP"
                    ),

                    "run": run_idx,
                    "frame": frame_idx,
                    "image": frame_path.name,

                    "e2e_ms": result[
                        "e2e_ms"
                    ],

                    "preprocess_ms": result[
                        "preprocess_ms"
                    ],

                    "inference_ms": result[
                        "inference_ms"
                    ],

                    "postprocess_ms": result[
                        "postprocess_ms"
                    ],

                    "box_extraction_ms": result[
                        "box_extraction_ms"
                    ],

                    "mqtt_delivery_ms": result[
                        "mqtt_delivery_ms"
                    ],

                    "num_detections": result[
                        "num_detections"
                    ],

                    "gt_count": len(
                        gt_boxes
                    ),

                    "tp": tp,
                    "fp": fp,
                    "fn": fn,
                }

                all_rows.append(
                    row
                )

                e2e_values.append(
                    result["e2e_ms"]
                )

                preprocess_values.append(
                    result[
                        "preprocess_ms"
                    ]
                )

                inference_values.append(
                    result[
                        "inference_ms"
                    ]
                )

                postprocess_values.append(
                    result[
                        "postprocess_ms"
                    ]
                )

                extraction_values.append(
                    result[
                        "box_extraction_ms"
                    ]
                )

                if (
                    result[
                        "mqtt_delivery_ms"
                    ]
                    is not None
                ):

                    mqtt_values.append(
                        result[
                            "mqtt_delivery_ms"
                        ]
                    )

            finally:

                del frame

            # ------------------------------------------------
            # Periodic cleanup OUTSIDE timing.
            # ------------------------------------------------

            if (
                frame_idx % 25
                == 0
            ):

                release_memory()

                if (
                    frame_idx % 250
                    == 0
                ):

                    print(
                        f"Processed "
                        f"{frame_idx}/"
                        f"{len(frame_paths)} "
                        f"frames"
                    )

        # ====================================================
        # MOT METRICS
        # ====================================================

        precision, recall, f1 = (
            metrics_from_counts(
                tp_total,
                fp_total,
                fn_total,
            )
        )

        run_summary = {

            "run": run_idx,

            "frames": len(
                e2e_values
            ),

            "e2e_mean_ms":
                mean_or_nan(
                    e2e_values
                ),

            "e2e_sd_ms":
                sd_or_nan(
                    e2e_values
                ),

            "e2e_p95_ms":
                percentile(
                    e2e_values,
                    95,
                ),

            "e2e_p99_ms":
                percentile(
                    e2e_values,
                    99,
                ),

            "e2e_median_ms":
                percentile(
                    e2e_values,
                    50,
                ),

            "equivalent_fps":
                equivalent_fps(
                    mean_or_nan(
                        e2e_values
                    )
                ),

            "preprocess_mean_ms":
                mean_or_nan(
                    preprocess_values
                ),

            "preprocess_sd_ms":
                sd_or_nan(
                    preprocess_values
                ),

            "inference_mean_ms":
                mean_or_nan(
                    inference_values
                ),

            "inference_sd_ms":
                sd_or_nan(
                    inference_values
                ),

            "postprocess_mean_ms":
                mean_or_nan(
                    postprocess_values
                ),

            "postprocess_sd_ms":
                sd_or_nan(
                    postprocess_values
                ),

            "box_extraction_mean_ms":
                mean_or_nan(
                    extraction_values
                ),

            "box_extraction_sd_ms":
                sd_or_nan(
                    extraction_values
                ),

            "mqtt_delivery_mean_ms":
                (
                    mean_or_nan(
                        mqtt_values
                    )
                    if mqtt_values
                    else None
                ),

            "mqtt_delivery_sd_ms":
                (
                    sd_or_nan(
                        mqtt_values
                    )
                    if mqtt_values
                    else None
                ),

            # ------------------------------------------------
            # MOT accuracy
            # ------------------------------------------------

            "TP": int(
                tp_total
            ),

            "FP": int(
                fp_total
            ),

            "FN": int(
                fn_total
            ),

            "precision": float(
                precision
            ),

            "recall": float(
                recall
            ),

            "f1": float(
                f1
            ),
        }

        run_summaries.append(
            run_summary
        )

        # ====================================================
        # PRINT RUN
        # ====================================================

        print(
            f"Mean E2E: "
            f"{run_summary['e2e_mean_ms']:.6f} ms"
        )

        print(
            f"SD: "
            f"{run_summary['e2e_sd_ms']:.6f} ms"
        )

        print(
            f"P95: "
            f"{run_summary['e2e_p95_ms']:.6f} ms"
        )

        print(
            f"P99: "
            f"{run_summary['e2e_p99_ms']:.6f} ms"
        )

        print(
            f"FPS: "
            f"{run_summary['equivalent_fps']:.6f}"
        )

        print(
            f"YOLO preprocess: "
            f"{run_summary['preprocess_mean_ms']:.6f} ms"
        )

        print(
            f"YOLO inference: "
            f"{run_summary['inference_mean_ms']:.6f} ms"
        )

        print(
            f"YOLO postprocess: "
            f"{run_summary['postprocess_mean_ms']:.6f} ms"
        )

        print(
            f"Box extraction: "
            f"{run_summary['box_extraction_mean_ms']:.6f} ms"
        )

        print(
            f"TP={tp_total}, "
            f"FP={fp_total}, "
            f"FN={fn_total}"
        )

        print(
            f"Precision="
            f"{precision:.6f}"
        )

        print(
            f"Recall="
            f"{recall:.6f}"
        )

        print(
            f"F1="
            f"{f1:.6f}"
        )

        if mqtt_values:

            print(
                f"MQTT delivery: "
                f"{run_summary['mqtt_delivery_mean_ms']:.6f} ms"
            )

        release_memory()

    return (
        all_rows,
        run_summaries,
    )


# ============================================================
# AGGREGATE RUNTIME RESULTS
# ============================================================

def aggregate_runtime(
    all_rows,
    run_summaries,
    experiment,
    dataset,
):

    # ========================================================
    # SAFETY
    # ========================================================

    if not run_summaries:

        raise RuntimeError(
            "No run summaries were generated."
        )

    # ========================================================
    # RUN-LEVEL VALUES
    # ========================================================

    e2e_run_means = [
        r["e2e_mean_ms"]
        for r in run_summaries
    ]

    preprocess_run_means = [
        r["preprocess_mean_ms"]
        for r in run_summaries
    ]

    inference_run_means = [
        r["inference_mean_ms"]
        for r in run_summaries
    ]

    postprocess_run_means = [
        r["postprocess_mean_ms"]
        for r in run_summaries
    ]

    extraction_run_means = [
        r["box_extraction_mean_ms"]
        for r in run_summaries
    ]

    mqtt_run_means = [
        r["mqtt_delivery_mean_ms"]
        for r in run_summaries
        if (
            r["mqtt_delivery_mean_ms"]
            is not None
        )
    ]

    # ========================================================
    # FRAME-LEVEL VALUES
    # ========================================================

    e2e_all = [
        r["e2e_ms"]
        for r in all_rows
    ]

    preprocess_all = [
        r["preprocess_ms"]
        for r in all_rows
    ]

    inference_all = [
        r["inference_ms"]
        for r in all_rows
    ]

    postprocess_all = [
        r["postprocess_ms"]
        for r in all_rows
    ]

    extraction_all = [
        r["box_extraction_ms"]
        for r in all_rows
    ]

    mqtt_all = [
        r["mqtt_delivery_ms"]
        for r in all_rows
        if (
            r["mqtt_delivery_ms"]
            is not None
        )
    ]

    # ========================================================
    # CIs
    # ========================================================

    (
        e2e_ci_low,
        e2e_ci_high,
    ) = ci95(
        e2e_run_means
    )

    (
        prep_ci_low,
        prep_ci_high,
    ) = ci95(
        preprocess_run_means
    )

    (
        inf_ci_low,
        inf_ci_high,
    ) = ci95(
        inference_run_means
    )

    (
        post_ci_low,
        post_ci_high,
    ) = ci95(
        postprocess_run_means
    )

    (
        ext_ci_low,
        ext_ci_high,
    ) = ci95(
        extraction_run_means
    )

    # ========================================================
    # AGGREGATE
    # ========================================================

    aggregate = {

        "experiment": experiment,

        "dataset": dataset,

        "runs": len(
            run_summaries
        ),

        "frames_per_run": (
            run_summaries[0][
                "frames"
            ]
            if run_summaries
            else 0
        ),

        # ====================================================
        # E2E
        # ====================================================

        "e2e_mean_ms":
            mean_or_nan(
                e2e_run_means
            ),

        "e2e_sd_ms":
            sd_or_nan(
                e2e_run_means
            ),

        "e2e_ci95_low_ms":
            e2e_ci_low,

        "e2e_ci95_high_ms":
            e2e_ci_high,

        "e2e_pooled_median_ms":
            percentile(
                e2e_all,
                50,
            ),

        "e2e_pooled_p95_ms":
            percentile(
                e2e_all,
                95,
            ),

        "e2e_pooled_p99_ms":
            percentile(
                e2e_all,
                99,
            ),

        "e2e_pooled_min_ms":
            (
                min(e2e_all)
                if e2e_all
                else float("nan")
            ),

        "e2e_pooled_max_ms":
            (
                max(e2e_all)
                if e2e_all
                else float("nan")
            ),

        "equivalent_fps":
            equivalent_fps(
                mean_or_nan(
                    e2e_run_means
                )
            ),

        # ====================================================
        # PREPROCESS
        # ====================================================

        "yolo_preprocess_mean_ms":
            mean_or_nan(
                preprocess_run_means
            ),

        "yolo_preprocess_sd_ms":
            sd_or_nan(
                preprocess_run_means
            ),

        "yolo_preprocess_ci95_low_ms":
            prep_ci_low,

        "yolo_preprocess_ci95_high_ms":
            prep_ci_high,

        "yolo_preprocess_p95_ms":
            percentile(
                preprocess_all,
                95,
            ),

        "yolo_preprocess_p99_ms":
            percentile(
                preprocess_all,
                99,
            ),

        # ====================================================
        # INFERENCE
        # ====================================================

        "yolo_inference_mean_ms":
            mean_or_nan(
                inference_run_means
            ),

        "yolo_inference_sd_ms":
            sd_or_nan(
                inference_run_means
            ),

        "yolo_inference_ci95_low_ms":
            inf_ci_low,

        "yolo_inference_ci95_high_ms":
            inf_ci_high,

        "yolo_inference_p95_ms":
            percentile(
                inference_all,
                95,
            ),

        "yolo_inference_p99_ms":
            percentile(
                inference_all,
                99,
            ),

        # ====================================================
        # POSTPROCESS
        # ====================================================

        "yolo_postprocess_mean_ms":
            mean_or_nan(
                postprocess_run_means
            ),

        "yolo_postprocess_sd_ms":
            sd_or_nan(
                postprocess_run_means
            ),

        "yolo_postprocess_ci95_low_ms":
            post_ci_low,

        "yolo_postprocess_ci95_high_ms":
            post_ci_high,

        "yolo_postprocess_p95_ms":
            percentile(
                postprocess_all,
                95,
            ),

        "yolo_postprocess_p99_ms":
            percentile(
                postprocess_all,
                99,
            ),

        # ====================================================
        # BOX EXTRACTION
        # ====================================================

        "box_extraction_mean_ms":
            mean_or_nan(
                extraction_run_means
            ),

        "box_extraction_sd_ms":
            sd_or_nan(
                extraction_run_means
            ),

        "box_extraction_ci95_low_ms":
            ext_ci_low,

        "box_extraction_ci95_high_ms":
            ext_ci_high,

        "box_extraction_p95_ms":
            percentile(
                extraction_all,
                95,
            ),

        "box_extraction_p99_ms":
            percentile(
                extraction_all,
                99,
            ),

        # ====================================================
        # MQTT
        # ====================================================

        "mqtt_delivery_mean_ms":
            (
                mean_or_nan(
                    mqtt_run_means
                )
                if mqtt_run_means
                else None
            ),

        "mqtt_delivery_sd_ms":
            (
                sd_or_nan(
                    mqtt_run_means
                )
                if mqtt_run_means
                else None
            ),

        "mqtt_delivery_ci95_low_ms":
            (
                ci95(
                    mqtt_run_means
                )[0]
                if mqtt_run_means
                else None
            ),

        "mqtt_delivery_ci95_high_ms":
            (
                ci95(
                    mqtt_run_means
                )[1]
                if mqtt_run_means
                else None
            ),

        "mqtt_delivery_pooled_p95_ms":
            (
                percentile(
                    mqtt_all,
                    95,
                )
                if mqtt_all
                else None
            ),

        "mqtt_delivery_pooled_p99_ms":
            (
                percentile(
                    mqtt_all,
                    99,
                )
                if mqtt_all
                else None
            ),
    }

    # ========================================================
    # MOT ACCURACY
    # ========================================================

    dataset_upper = str(
        dataset
    ).upper()

    if dataset_upper.startswith(
        "MOT"
    ):

        total_tp = sum(
            int(
                r.get(
                    "TP",
                    0,
                )
            )
            for r in run_summaries
        )

        total_fp = sum(
            int(
                r.get(
                    "FP",
                    0,
                )
            )
            for r in run_summaries
        )

        total_fn = sum(
            int(
                r.get(
                    "FN",
                    0,
                )
            )
            for r in run_summaries
        )

        precision, recall, f1 = (
            metrics_from_counts(
                total_tp,
                total_fp,
                total_fn,
            )
        )

        # IMPORTANT:
        # These values are now always inserted into
        # the aggregate dictionary for MOT.
        aggregate.update({

            "TP": int(
                total_tp
            ),

            "FP": int(
                total_fp
            ),

            "FN": int(
                total_fn
            ),

            "precision": float(
                precision
            ),

            "recall": float(
                recall
            ),

            "f1": float(
                f1
            ),
        })

    return aggregate


# ============================================================
# COCO ACCURACY
# ============================================================

def calculate_coco_accuracy(
    model,
    coco_yaml,
    img_size,
    conf,
    iou,
):

    print_separator()

    print(
        "COCO ACCURACY EVALUATION"
    )

    print_separator()

    release_memory()

    if not coco_yaml:

        print(
            "[WARNING] --coco-yaml was not supplied."
        )

        return {

            "precision": None,
            "recall": None,
            "f1": None,
            "mAP50": None,
            "mAP50_95": None,
        }

    try:

        metrics = model.val(

            data=coco_yaml,

            imgsz=img_size,

            conf=conf,

            iou=iou,

            batch=1,

            device="cpu",

            workers=0,

            plots=False,

            save_json=False,

            verbose=False,
        )

        box_metrics = metrics.box

        precision = float(
            np.mean(
                box_metrics.p
            )
        )

        recall = float(
            np.mean(
                box_metrics.r
            )
        )

        map50 = float(
            box_metrics.map50
        )

        map5095 = float(
            box_metrics.map
        )

        if (
            precision
            + recall
            > 0
        ):

            f1 = (
                2.0
                * precision
                * recall
                / (
                    precision
                    + recall
                )
            )

        else:

            f1 = 0.0

        result = {

            "precision": precision,

            "recall": recall,

            "f1": f1,

            "mAP50": map50,

            "mAP50_95": map5095,
        }

        print(
            f"Precision       = "
            f"{precision:.6f}"
        )

        print(
            f"Recall          = "
            f"{recall:.6f}"
        )

        print(
            f"F1              = "
            f"{f1:.6f}"
        )

        print(
            f"mAP@0.5         = "
            f"{map50:.6f}"
        )

        print(
            f"mAP@0.5:0.95    = "
            f"{map5095:.6f}"
        )

        release_memory()

        return result

    except Exception as e:

        print(
            "[WARNING] COCO validation failed:"
        )

        print(
            repr(e)
        )

        return {

            "precision": None,
            "recall": None,
            "f1": None,
            "mAP50": None,
            "mAP50_95": None,
        }


# ============================================================
# A -> B OVERHEAD
# ============================================================

def calculate_ab_overhead(
    a_json,
    b_aggregate,
):

    if not a_json:
        return None

    if not os.path.exists(
        a_json
    ):

        print(
            "[INFO] Baseline JSON not found: "
            f"{a_json}"
        )

        return None

    with open(
        a_json,
        "r",
        encoding="utf-8",
    ) as f:

        a_data = json.load(f)

    # --------------------------------------------------------
    # Support both:
    #
    #   final JSON containing final.e2e_mean_ms
    #
    # and older JSON where these fields may be at top level.
    # --------------------------------------------------------

    a_final = a_data.get(
        "final",
        a_data,
    )

    a_mean = a_final.get(
        "e2e_mean_ms"
    )

    a_p95 = a_final.get(
        "e2e_pooled_p95_ms"
    )

    a_p99 = a_final.get(
        "e2e_pooled_p99_ms"
    )

    b_mean = b_aggregate.get(
        "e2e_mean_ms"
    )

    b_p95 = b_aggregate.get(
        "e2e_pooled_p95_ms"
    )

    b_p99 = b_aggregate.get(
        "e2e_pooled_p99_ms"
    )

    if (
        a_mean is None
        or b_mean is None
    ):

        print(
            "[WARNING] Could not calculate "
            "A->B overhead because A or B "
            "E2E mean is missing."
        )

        return None

    delta = (
        b_mean
        - a_mean
    )

    overhead_percent = (
        delta
        / a_mean
        * 100.0
        if a_mean > 0
        else float("nan")
    )

    result = {

        "A_mean_ms": a_mean,

        "B_mean_ms": b_mean,

        "A_to_B_delta_ms": delta,

        "A_to_B_overhead_percent":
            overhead_percent,

        "A_p95_ms": a_p95,

        "B_p95_ms": b_p95,

        "A_p95_delta_ms": (
            b_p95 - a_p95
            if (
                a_p95 is not None
                and b_p95 is not None
            )
            else None
        ),

        "A_p99_ms": a_p99,

        "B_p99_ms": b_p99,

        "A_p99_delta_ms": (
            b_p99 - a_p99
            if (
                a_p99 is not None
                and b_p99 is not None
            )
            else None
        ),

        "interpretation":
            "Measured system-level A-to-B "
            "difference; not isolated MQTT latency.",
    }

    return result


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Unified YOLOChain "
            "Experiment A/B"
        )
    )

    parser.add_argument(
        "--experiment",
        required=True,
        choices=[
            "A",
            "B",
        ],
    )

    parser.add_argument(
        "--dataset",
        required=True,
        choices=[
            "coco",
            "mot",
        ],
    )

    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
    )

    parser.add_argument(
        "--input-dir",
        default=None,
        help=(
            "COCO image directory"
        ),
    )

    parser.add_argument(
        "--frames-dir",
        default=None,
        help=(
            "MOT img1 directory"
        ),
    )

    parser.add_argument(
        "--gt-file",
        default=None,
        help=(
            "MOT gt.txt"
        ),
    )

    parser.add_argument(
        "--coco-yaml",
        default=None,
        help=(
            "COCO YAML for mAP evaluation"
        ),
    )

    parser.add_argument(
        "--results-dir",
        required=True,
    )

    parser.add_argument(
        "--img-size",
        type=int,
        default=DEFAULT_IMG_SIZE,
    )

    parser.add_argument(
        "--conf",
        type=float,
        default=DEFAULT_CONF,
    )

    parser.add_argument(
        "--iou",
        type=float,
        default=DEFAULT_IOU,
    )

    parser.add_argument(
        "--runs",
        type=int,
        default=DEFAULT_RUNS,
    )

    parser.add_argument(
        "--warmup",
        type=int,
        default=DEFAULT_WARMUP,
    )

    parser.add_argument(
        "--mqtt-host",
        default=DEFAULT_MQTT_HOST,
    )

    parser.add_argument(
        "--mqtt-port",
        type=int,
        default=DEFAULT_MQTT_PORT,
    )

    parser.add_argument(
        "--mqtt-topic",
        default=DEFAULT_MQTT_TOPIC,
    )

    parser.add_argument(
        "--mqtt-qos",
        type=int,
        default=DEFAULT_MQTT_QOS,
    )

    parser.add_argument(
        "--mqtt-retain",
        action="store_true",
    )

    parser.add_argument(
        "--mqtt-timeout",
        type=float,
        default=5.0,
    )

    parser.add_argument(
        "--baseline-json",
        default=None,
        help=(
            "Experiment A final JSON, "
            "used for A->B overhead "
            "calculation"
        ),
    )

    args = parser.parse_args()

    ensure_dir(
        args.results_dir
    )

    print_separator()

    print(
        "YOLOChain — Unified "
        "Experiment A/B"
    )

    print_separator()

    print(
        f"Experiment       : "
        f"{args.experiment}"
    )

    print(
        f"Dataset           : "
        f"{args.dataset}"
    )

    print(
        f"Model             : "
        f"{args.model}"
    )

    print(
        f"Image size        : "
        f"{args.img_size}"
    )

    print(
        f"Confidence        : "
        f"{args.conf}"
    )

    print(
        f"IoU               : "
        f"{args.iou}"
    )

    print(
        f"Runs              : "
        f"{args.runs}"
    )

    print(
        f"Warmup            : "
        f"{args.warmup}"
    )

    print(
        "Device            : CPU"
    )

    print(
        "Image loading     : "
        "excluded from timing"
    )

    print(
        "GT matching       : "
        "excluded from timing"
    )

    print(
        "Accuracy calc     : "
        "excluded from timing"
    )

    print(
        "E2E               : "
        "direct wall-clock measurement"
    )

    print(
        "Box extraction    : "
        "extraction-only timing"
    )

    # ========================================================
    # LOAD MODEL
    # ========================================================

    model = load_model(
        args.model
    )

    # ========================================================
    # MQTT
    # ========================================================

    mqtt_receiver = None
    mqtt_publisher = None

    if (
        args.experiment
        == "B"
    ):

        mqtt_receiver = (
            MQTTReceiver(
                args.mqtt_host,
                args.mqtt_port,
                args.mqtt_topic,
            )
        )

        mqtt_publisher = (
            MQTTPublisher(
                args.mqtt_host,
                args.mqtt_port,
                args.mqtt_topic,
                qos=args.mqtt_qos,
                retain=args.mqtt_retain,
            )
        )

    try:

        # ====================================================
        # COCO
        # ====================================================

        if (
            args.dataset
            == "coco"
        ):

            if not args.input_dir:

                raise ValueError(
                    "--input-dir is required "
                    "for COCO"
                )

            image_paths = (
                find_images(
                    args.input_dir
                )
            )

            if not image_paths:

                raise RuntimeError(
                    "No COCO images found."
                )

            print(
                f"[COCO] Images: "
                f"{len(image_paths)}"
            )

            # COCO:
            # all YOLO classes

            classes = None

            (
                all_rows,
                run_summaries,
            ) = run_coco_runtime(

                model=model,

                image_paths=image_paths,

                experiment=args.experiment,

                img_size=args.img_size,

                conf=args.conf,

                iou=args.iou,

                classes=classes,

                runs=args.runs,

                warmup=args.warmup,

                mqtt_publisher=(
                    mqtt_publisher
                ),

                mqtt_receiver=(
                    mqtt_receiver
                ),

                mqtt_timeout=(
                    args.mqtt_timeout
                ),
            )

            aggregate = (
                aggregate_runtime(

                    all_rows=all_rows,

                    run_summaries=(
                        run_summaries
                    ),

                    experiment=(
                        args.experiment
                    ),

                    dataset="COCO128",
                )
            )

            # ------------------------------------------------
            # Accuracy is separate from timing.
            # ------------------------------------------------

            coco_accuracy = (
                calculate_coco_accuracy(

                    model=model,

                    coco_yaml=(
                        args.coco_yaml
                    ),

                    img_size=(
                        args.img_size
                    ),

                    conf=args.conf,

                    iou=args.iou,
                )
            )

            aggregate.update({

                "precision":
                    coco_accuracy[
                        "precision"
                    ],

                "recall":
                    coco_accuracy[
                        "recall"
                    ],

                "f1":
                    coco_accuracy[
                        "f1"
                    ],

                "mAP50":
                    coco_accuracy[
                        "mAP50"
                    ],

                "mAP50_95":
                    coco_accuracy[
                        "mAP50_95"
                    ],
            })

        # ====================================================
        # MOT
        # ====================================================

        else:

            if not args.frames_dir:

                raise ValueError(
                    "--frames-dir is required "
                    "for MOT"
                )

            if not args.gt_file:

                raise ValueError(
                    "--gt-file is required "
                    "for MOT"
                )

            frame_paths = (
                find_images(
                    args.frames_dir
                )
            )

            if not frame_paths:

                raise RuntimeError(
                    "No MOT frames found."
                )

            print(
                f"[MOT] Frames: "
                f"{len(frame_paths)}"
            )

            print(
                f"[MOT] Loading GT: "
                f"{args.gt_file}"
            )

            gt = load_mot_gt(
                args.gt_file
            )

            print(
                f"[MOT] GT frames: "
                f"{len(gt)}"
            )

            # ------------------------------------------------
            # MOT17 pedestrian only.
            #
            # YOLOv8 COCO class 0 = person.
            # ------------------------------------------------

            classes = [0]

            (
                all_rows,
                run_summaries,
            ) = run_mot_runtime(

                model=model,

                frame_paths=frame_paths,

                gt=gt,

                experiment=args.experiment,

                img_size=args.img_size,

                conf=args.conf,

                iou=args.iou,

                classes=classes,

                runs=args.runs,

                warmup=args.warmup,

                mqtt_publisher=(
                    mqtt_publisher
                ),

                mqtt_receiver=(
                    mqtt_receiver
                ),

                mqtt_timeout=(
                    args.mqtt_timeout
                ),
            )

            aggregate = (
                aggregate_runtime(

                    all_rows=all_rows,

                    run_summaries=(
                        run_summaries
                    ),

                    experiment=(
                        args.experiment
                    ),

                    dataset=(
                        "MOT17-04-SDP"
                    ),
                )
            )

        # ====================================================
        # A -> B OVERHEAD
        # ====================================================

        ab_overhead = None

        if (
            args.experiment
            == "B"
            and args.baseline_json
        ):

            ab_overhead = (
                calculate_ab_overhead(
                    args.baseline_json,
                    aggregate,
                )
            )

            if (
                ab_overhead
                is not None
            ):

                aggregate[
                    "A_to_B_overhead"
                ] = ab_overhead

        # ====================================================
        # SAVE RAW FRAME CSV
        # ====================================================

        raw_csv = os.path.join(

            args.results_dir,

            f"{args.experiment}_"
            f"{args.dataset}_"
            f"frame_level_raw.csv",
        )

        if (
            args.dataset
            == "coco"
        ):

            fields = [

                "experiment",
                "dataset",
                "run",
                "frame",
                "image",

                "e2e_ms",

                "preprocess_ms",
                "inference_ms",
                "postprocess_ms",

                "box_extraction_ms",

                "mqtt_delivery_ms",

                "num_detections",
            ]

        else:

            fields = [

                "experiment",
                "dataset",
                "run",
                "frame",
                "image",

                "e2e_ms",

                "preprocess_ms",
                "inference_ms",
                "postprocess_ms",

                "box_extraction_ms",

                "mqtt_delivery_ms",

                "num_detections",

                "gt_count",

                "tp",
                "fp",
                "fn",
            ]

        write_csv(
            raw_csv,
            all_rows,
            fields,
        )

        print(
            f"[SAVED] {raw_csv}"
        )

        # ====================================================
        # SAVE RUN SUMMARY CSV
        # ====================================================

        run_csv = os.path.join(

            args.results_dir,

            f"{args.experiment}_"
            f"{args.dataset}_"
            f"run_summary.csv",
        )

        run_fields = sorted(
            {
                key
                for row
                in run_summaries
                for key
                in row.keys()
            }
        )

        write_csv(
            run_csv,
            run_summaries,
            run_fields,
        )

        print(
            f"[SAVED] {run_csv}"
        )

        # ====================================================
        # SAVE FINAL JSON
        # ====================================================

        final_json = os.path.join(

            args.results_dir,

            f"{args.experiment}_"
            f"{args.dataset}_"
            f"FINAL.json",
        )

        final_output = {

            "configuration": {

                "experiment":
                    args.experiment,

                "dataset":
                    args.dataset,

                "model":
                    args.model,

                "img_size":
                    args.img_size,

                "confidence":
                    args.conf,

                "iou":
                    args.iou,

                "runs":
                    args.runs,

                "warmup":
                    args.warmup,

                "device":
                    "cpu",

                "batch_size":
                    1,

                "image_loading_excluded":
                    True,

                "gt_matching_excluded":
                    True,

                "accuracy_calculation_excluded":
                    True,

                "mot_matching_iou":
                    (
                        MOT_IOU_MATCH
                        if (
                            args.dataset
                            == "mot"
                        )
                        else None
                    ),

                "mot_class":
                    (
                        "person"
                        if (
                            args.dataset
                            == "mot"
                        )
                        else None
                    ),

                "mqtt":
                    (
                        {
                            "host":
                                args.mqtt_host,

                            "port":
                                args.mqtt_port,

                            "topic":
                                args.mqtt_topic,

                            "qos":
                                args.mqtt_qos,

                            "retain":
                                args.mqtt_retain,
                        }
                        if (
                            args.experiment
                            == "B"
                        )
                        else None
                    ),
            },

            "run_summaries":
                run_summaries,

            "final":
                aggregate,
        }

        # ----------------------------------------------------
        # SAVE BEFORE FINAL SCREEN
        # ----------------------------------------------------

        save_json(
            final_json,
            final_output,
        )

        print(
            f"[SAVED] {final_json}"
        )

        # ====================================================
        # FINAL SCREEN
        # ====================================================

        print_separator()

        print(
            "FINAL RESULTS"
        )

        print_separator()

        print(
            f"Mean E2E       : "
            f"{aggregate['e2e_mean_ms']:.6f} ms"
        )

        print(
            f"SD             : "
            f"{aggregate['e2e_sd_ms']:.6f} ms"
        )

        print(
            f"95% CI         : "
            f"{aggregate['e2e_ci95_low_ms']:.6f} - "
            f"{aggregate['e2e_ci95_high_ms']:.6f} ms"
        )

        print(
            f"Pooled P95     : "
            f"{aggregate['e2e_pooled_p95_ms']:.6f} ms"
        )

        print(
            f"Pooled P99     : "
            f"{aggregate['e2e_pooled_p99_ms']:.6f} ms"
        )

        print(
            f"Equivalent FPS : "
            f"{aggregate['equivalent_fps']:.6f}"
        )

        print_separator()

        print(
            f"YOLO preprocess: "
            f"{aggregate['yolo_preprocess_mean_ms']:.6f} ms"
        )

        print(
            f"YOLO inference : "
            f"{aggregate['yolo_inference_mean_ms']:.6f} ms"
        )

        print(
            f"YOLO postproc  : "
            f"{aggregate['yolo_postprocess_mean_ms']:.6f} ms"
        )

        print(
            f"Box extraction : "
            f"{aggregate['box_extraction_mean_ms']:.6f} ms"
        )

        # ====================================================
        # MQTT
        # ====================================================

        if (
            aggregate[
                "mqtt_delivery_mean_ms"
            ]
            is not None
        ):

            print_separator()

            print(
                f"MQTT delivery  : "
                f"{aggregate['mqtt_delivery_mean_ms']:.6f} ms"
            )

            print(
                f"MQTT SD        : "
                f"{aggregate['mqtt_delivery_sd_ms']:.6f} ms"
            )

            print(
                f"MQTT 95% CI    : "
                f"{aggregate['mqtt_delivery_ci95_low_ms']:.6f} - "
                f"{aggregate['mqtt_delivery_ci95_high_ms']:.6f} ms"
            )

        # ====================================================
        # COCO ACCURACY
        # ====================================================

        if (
            args.dataset
            == "coco"
        ):

            print_separator()

            print(
                f"Precision      : "
                f"{aggregate['precision']:.6f}"
            )

            print(
                f"Recall         : "
                f"{aggregate['recall']:.6f}"
            )

            print(
                f"F1             : "
                f"{aggregate['f1']:.6f}"
            )

            print(
                f"mAP@0.5        : "
                f"{aggregate['mAP50']:.6f}"
            )

            print(
                f"mAP@0.5:0.95   : "
                f"{aggregate['mAP50_95']:.6f}"
            )

        # ====================================================
        # MOT ACCURACY
        # ====================================================

        else:

            print_separator()

            # ------------------------------------------------
            # Explicit existence check to prevent KeyError.
            # ------------------------------------------------

            if not all(
                key in aggregate
                for key in (
                    "TP",
                    "FP",
                    "FN",
                    "precision",
                    "recall",
                    "f1",
                )
            ):

                raise RuntimeError(
                    "MOT aggregate accuracy "
                    "metrics are missing."
                )

            print(
                f"TP             : "
                f"{aggregate['TP']}"
            )

            print(
                f"FP             : "
                f"{aggregate['FP']}"
            )

            print(
                f"FN             : "
                f"{aggregate['FN']}"
            )

            print(
                f"Precision      : "
                f"{aggregate['precision']:.6f}"
            )

            print(
                f"Recall         : "
                f"{aggregate['recall']:.6f}"
            )

            print(
                f"F1             : "
                f"{aggregate['f1']:.6f}"
            )

        # ====================================================
        # A -> B
        # ====================================================

        if (
            ab_overhead
            is not None
        ):

            print_separator()

            print(
                "A -> B "
                "SYSTEM-LEVEL DIFFERENCE"
            )

            print_separator()

            print(
                f"A mean         : "
                f"{ab_overhead['A_mean_ms']:.6f} ms"
            )

            print(
                f"B mean         : "
                f"{ab_overhead['B_mean_ms']:.6f} ms"
            )

            print(
                f"Delta          : "
                f"{ab_overhead['A_to_B_delta_ms']:.6f} ms"
            )

            print(
                f"Overhead       : "
                f"{ab_overhead['A_to_B_overhead_percent']:.6f}%"
            )

            print(
                "NOTE: This is the measured "
                "A-to-B system-level difference, "
                "not isolated MQTT latency."
            )

        print_separator()

        print(
            "Experiment completed successfully."
        )

        print_separator()

    finally:

        # ====================================================
        # CLOSE MQTT
        # ====================================================

        if (
            mqtt_publisher
            is not None
        ):

            mqtt_publisher.close()

        if (
            mqtt_receiver
            is not None
        ):

            mqtt_receiver.close()

        # ====================================================
        # RELEASE MODEL
        # ====================================================

        try:

            del model

        except Exception:

            pass

        release_memory()


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()
