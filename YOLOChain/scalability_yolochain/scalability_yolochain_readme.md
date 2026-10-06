# YOLOChain Validator Scalability

This directory contains the implementation used to evaluate the scalability of the YOLOChain validator network.

The scalability experiment uses the YOLOChain Experiment D implementation with different numbers of validators.

## Validator Configurations

The evaluated configurations are:

* V2 — 2 validators
* V4 — 4 validators
* V6 — 6 validators
* V8 — 8 validators

The camera configuration remains fixed at two cameras.

## Requirements

The experiment requires:

* Python 3
* Node.js
* Mosquitto MQTT broker
* YOLOv8
* YOLOChain PQC shared library
* COCO128 and/or MOT17-04-SDP

## Starting the Network

Start Validator 1:


VALIDATOR_ID=1 NODE_ID=validator_1 \
node r_mqtt_app_D_nv_fixed.js


Start Validator 2:


VALIDATOR_ID=2 NODE_ID=validator_2 \
node p2p_blockchain_D_nv_fixed.js


Start Validator 3:


VALIDATOR_ID=3 NODE_ID=validator_3 \
node p2p_blockchain_D_nv_fixed.js


Start Validator 4:


VALIDATOR_ID=4 NODE_ID=validator_4 \
node p2p_blockchain_D_nv_fixed.js


Additional validator instances are started according to the configuration being evaluated.

## Checking the Camera Script

Before running the camera experiment:


python3 -m py_compile r_camera_yolo_recovery_D_fixed.py


---

# COCO128

Run:


python3 r_camera_yolo_recovery_D_fixed.py \
  --dataset coco128 \
  --input-dir "/path/to/coco128/images/train2017" \
  --camera-id camera_01 \
  --model yolov8n.pt \
  --img-size 416 \
  --conf 0.25 \
  --iou 0.50 \
  --broker localhost \
  --port 1883 \
  --topic pqc/handshake \
  --algo-code 2 \
  --algo-name falcon-512 \
  --pqc-library ./r1_sign_lib.so \
  --pbft-metrics-file results_D/validator_1/results/pbft_metrics.csv \
  --pbft-timeout 20 \
  --recovery-timeout 10 \
  --max-retries 10 \
  --max-images 128 \
  --results-dir results_D \
  --runs 5 \
  --no-display


---

# MOT17-04-SDP

Run:


python3 r_camera_yolo_recovery_D_fixed.py \
  --dataset mot17 \
  --input-dir "/path/to/MOT17-04-SDP/img1" \
  --camera-id camera_02 \
  --model yolov8n.pt \
  --img-size 416 \
  --conf 0.25 \
  --iou 0.50 \
  --broker localhost \
  --port 1883 \
  --topic pqc/handshake \
  --algo-code 2 \
  --algo-name falcon-512 \
  --pqc-library ./r1_sign_lib.so \
  --pbft-metrics-file results_D/validator_1/results/pbft_metrics.csv \
  --pbft-timeout 20 \
  --recovery-timeout 10 \
  --max-retries 100 \
  --results-dir results_D \
  --no-display


## Notes

The scalability experiment reuses the YOLOChain Experiment D implementation while varying the number of validators.

Experimental result files are not included in this repository.
