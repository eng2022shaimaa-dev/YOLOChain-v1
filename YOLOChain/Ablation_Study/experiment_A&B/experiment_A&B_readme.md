# Experiments A and B

This directory contains the implementation for:

* Experiment A — YOLOv8
* Experiment B — YOLOv8 + MQTT

Both experiments use the same YOLOv8 configuration.

## Experiment A — COCO128


python3 unified_experiment_AB.py \
  --experiment A \
  --dataset coco \
  --input-dir "/path/to/coco128/images/train2017" \
  --coco-yaml "/path/to/coco128.yaml" \
  --results-dir results/unified_A_COCO128


## Experiment B — COCO128


python3 unified_experiment_AB.py \
  --experiment B \
  --dataset coco \
  --input-dir "/path/to/coco128/images/train2017" \
  --coco-yaml "/path/to/coco128.yaml" \
  --results-dir results/unified_B_COCO128


## Experiment A — MOT17-04-SDP

python3 unified_experiment_AB.py \
  --experiment A \
  --dataset mot \
  --frames-dir "/path/to/MOT17-04-SDP/img1" \
  --gt-file "/path/to/MOT17-04-SDP/gt/gt.txt" \
  --results-dir results/unified_A_MOT17_04_SDP


## Experiment B — MOT17-04-SDP


python3 unified_experiment_AB.py \
  --experiment B \
  --dataset mot \
  --frames-dir "/path/to/MOT17-04-SDP/img1" \
  --gt-file "/path/to/MOT17-04-SDP/gt/gt.txt" \
  --results-dir results/unified_B_MOT17_04_SDP


## Experimental Configuration

* YOLOv8n
* 416 × 416 input resolution
* Confidence threshold: 0.25
* IoU threshold: 0.50
* Batch size: 1
* 10 warm-up iterations
* 5 independent runs
* CPU execution
* CUDA disabled

The result directories are generated during execution and are not included in the repository.
