# Experiment D — YOLOChain

Experiment D represents the complete YOLOChain configuration:

* YOLOv8n
* MQTT
* Post-quantum cryptography
* PBFT-style blockchain
* Recovery mechanism

## Starting the Network

Start Validator 1 / MQTT Gateway:


VALIDATOR_ID=1 \
NODE_ID=validator_1 \
node r_mqtt_app_D_nv_fixed.js


Start Validator 2:


VALIDATOR_ID=2 \
NODE_ID=validator_2 \
node p2p_blockchain_D_nv_fixed.js


Start Validator 3:


VALIDATOR_ID=3 \
NODE_ID=validator_3 \
node p2p_blockchain_D_nv_fixed.js


Start Validator 4:


VALIDATOR_ID=4 \
NODE_ID=validator_4 \
node p2p_blockchain_D_nv_fixed.js


Run the following commands in separate terminals.

## Verify the Camera Script


python3 -m py_compile r_camera_yolo_recovery_D_fixed.py


---

# COCO128


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
  --pqc-library "./PQC_library/r1_sign_lib.so" \
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
  --pqc-library "./PQC_library/r1_sign_lib.so" \
  --pbft-metrics-file results_D/validator_1/results/pbft_metrics.csv \
  --pbft-timeout 20 \
  --recovery-timeout 10 \
  --max-retries 100 \
  --results-dir results_D \
  --no-display


## Notes

The paths above use placeholders and must be changed to the local dataset locations.

The PQC shared library is located in:


PQC_library/r1_sign_lib.so


For rebuilding the library, see:


PQC_library/PQC_library_readme.md


Experimental result directories are not included in this repository.
