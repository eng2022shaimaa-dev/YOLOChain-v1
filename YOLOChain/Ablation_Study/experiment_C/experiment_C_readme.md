# Experiment C — YOLOv8 + MQTT + PBFT

This directory contains the implementation of Experiment C in the YOLOChain ablation study.

Experiment C extends Experiment B by adding the PBFT-style blockchain component without the PQC component used in Experiment D.

## Starting the Validators

### Validator 2

VALIDATOR_ID=2 \
NODE_ID=validator_2 \
RESULTS_ROOT=results_C_fixed \
PBFT_N=4 \
PORT_BASE=39000 \
node p2p_blockchain2_C_fixed_abc.js


### Validator 3


VALIDATOR_ID=3 \
NODE_ID=validator_3 \
RESULTS_ROOT=results_C_fixed \
PBFT_N=4 \
PORT_BASE=39000 \
node p2p_blockchain2_C_fixed_abc.js


### Validator 4


VALIDATOR_ID=4 \
NODE_ID=validator_4 \
RESULTS_ROOT=results_C_fixed \
PBFT_N=4 \
PORT_BASE=39000 \
node p2p_blockchain2_C_fixed_abc.js


### Validator 1 / MQTT Gateway


VALIDATOR_ID=1 \
NODE_ID=validator_1 \
RESULTS_ROOT=results_C_fixed \
PBFT_N=4 \
MQTT_BROKER=mqtt://localhost:1883 \
MQTT_TOPIC=yolochain/C \
node r_mqtt_app_C_fixed_abc.js


---

## COCO128 E2E Experiment


python3 experiment_C_E2E.py \
  --dataset coco128 \
  --model yolov8n.pt \
  --input-dir "/path/to/coco128/images/train2017" \
  --broker 127.0.0.1 \
  --port 1883 \
  --topic "yolochain/C" \
  --mqtt-qos 1 \
  --results-dir "results_C_E2E_COCO128" \
  --canonical-results-dir "results_C_fixed"
```

## MOT17-04-SDP E2E Experiment


python3 experiment_C_E2E.py \
  --dataset mot \
  --model yolov8n.pt \
  --input-dir "/path/to/MOT17-04-SDP/img1" \
  --broker 127.0.0.1 \
  --port 1883 \
  --topic "yolochain/C" \
  --mqtt-qos 1 \
  --results-dir "results_C_E2E_MOT17" \
  --canonical-results-dir "results_C_fixed"


## Notes

Run each validator in a separate terminal.

The MQTT broker must be running before starting the gateway.

Experimental result directories are not included in this repository.
