# YOLOChain Security Evaluation

This directory contains the implementation used to evaluate the five security scenarios of YOLOChain.

## Security Scenarios

* S1 — Replay
* S2 — Modified metadata
* S3 — Fake camera
* S4 — MITM/message tampering
* S5 — Off-chain data tampering

## Requirements

The security experiments require:

* Python 3
* Node.js
* Mosquitto MQTT broker
* YOLOv8 environment
* YOLOChain PQC shared library
* COCO128 dataset

Before starting an experiment, make sure that the MQTT broker is running and that the required PQC library is available.

---

# Preparing the Results Directory

Before starting a new security experiment:


rm -rf results_D_security
mkdir -p results_D_security


---

# S1 — Replay

Start Validator 2:


RESULTS_ROOT=results_D_security \
SECURITY_MODE=1 \
SECURITY_TEST=S1 \
SECURITY_TAMPER_P2P_ONCE=0 \
VALIDATOR_ID=2 \
NODE_ID=validator_2 \
node p2p_blockchain_D_sec.js


Start Validator 3:


RESULTS_ROOT=results_D_security \
SECURITY_MODE=1 \
SECURITY_TEST=S1 \
SECURITY_TAMPER_P2P_ONCE=0 \
VALIDATOR_ID=3 \
NODE_ID=validator_3 \
node p2p_blockchain_D_sec.js


Start Validator 4:


RESULTS_ROOT=results_D_security \
SECURITY_MODE=1 \
SECURITY_TEST=S1 \
SECURITY_TAMPER_P2P_ONCE=0 \
VALIDATOR_ID=4 \
NODE_ID=validator_4 \
node p2p_blockchain_D_sec.js


Start Validator 1 / MQTT gateway:


RESULTS_ROOT=results_D_security \
SECURITY_MODE=1 \
SECURITY_TEST=S1 \
SECURITY_TAMPER_P2P_ONCE=0 \
VALIDATOR_ID=1 \
NODE_ID=validator_1 \
node r_mqtt_app_D_sec.js


Run the camera:

python3 r_camera_yolo_recovery_D_sec.py \
  --dataset coco128 \
  --input-dir "/path/to/coco128/images/train2017" \
  --camera-id camera_01 \
  --sequence 1000000 \
  --security-test S1 \
  --results-dir results_D_security


---

# S2 — Modified Metadata

Use the same validator and gateway configuration as S1, changing:


SECURITY_TEST=S2


Run:


python3 r_camera_yolo_recovery_D_sec.py \
  --dataset coco128 \
  --input-dir "/path/to/coco128/images/train2017" \
  --camera-id camera_01 \
  --sequence 1000000 \
  --security-test S2 \
  --results-dir results_D_security


---

# S3 — Fake Camera

Start Validators 2, 3, and 4 and the MQTT gateway as described above, using:


SECURITY_TEST=S3


Then run the fake-camera test:


python3 r_camera_yolo_recovery_D_sec.py \
  --dataset coco128 \
  --input-dir "/path/to/coco128/images/train2017" \
  --camera-id camera_01 \
  --sequence 1000000 \
  --security-test S3 \
  --attack-camera-id camera_fake \
  --results-dir results_D_security


---

# S4 — MITM / Message Tampering

For S4, use:


SECURITY_TEST=S4
SECURITY_TAMPER_P2P_ONCE=1


Start Validators 2, 3, and 4 and the MQTT gateway using these settings.

Then run:


python3 r_camera_yolo_recovery_D_sec.py \
  --dataset coco128 \
  --input-dir "/path/to/coco128/images/train2017" \
  --camera-id camera_01 \
  --sequence 1000000 \
  --security-test S4 \
  --results-dir results_D_security


---

# S5 — Off-chain Data Tampering

Use:


SECURITY_TEST=S5
SECURITY_TAMPER_P2P_ONCE=0


Start Validators 2, 3, and 4 and the MQTT gateway.

Then run:


python3 r_camera_yolo_recovery_D_sec.py \
  --dataset coco128 \
  --input-dir "/path/to/coco128/images/train2017" \
  --camera-id camera_01 \
  --sequence 1000000 \
  --security-test S5 \
  --results-dir results_D_security



## Dataset Paths

The paths shown above use placeholders:


/path/to/coco128/images/train2017


Replace this path with the local location of COCO128 on the system used for reproduction.

The absolute paths from the original experimental machine are intentionally not included in this repository.
