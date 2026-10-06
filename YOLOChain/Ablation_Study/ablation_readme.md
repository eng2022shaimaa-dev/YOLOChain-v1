# YOLOChain Ablation Study

This directory contains the implementations used for the YOLOChain ablation study.

The ablation study evaluates the incremental contribution of the main system components.

## Experiments

### Experiment A — YOLOv8

Baseline object detection using YOLOv8n without MQTT or blockchain processing.

Location:


experiment_A&B/


### Experiment B — YOLOv8 + MQTT

Extends Experiment A by adding MQTT communication.

Location:


experiment_A&B/


### Experiment C — YOLOv8 + MQTT + PBFT

Extends Experiment B by adding the PBFT-style blockchain component.

Location:


experiment_C/


### Experiment D — YOLOv8 + MQTT + PQC + PBFT

Complete YOLOChain experimental configuration, including:

* YOLOv8n
* MQTT
* post-quantum signatures
* PBFT-style blockchain
* recovery mechanism

Location:


experiment_D/


---

## Common Experimental Configuration

The ablation experiments use:

* YOLOv8n
* Input resolution: 416 × 416
* Confidence threshold: 0.25
* IoU threshold: 0.50
* Batch size: 1
* 10 warm-up iterations
* 5 independent runs
* CPU execution
* CUDA disabled

## Datasets

The experiments use:

* COCO128
* MOT17-04-SDP

Dataset paths must be changed to the local paths on the reproduction system.

## Execution

Detailed commands for each experiment are provided in:


experiment_A&B/experiment_A&B_readme.md
experiment_C/experiment_C_readme.md
experiment_D/experiment_D_readme.md


Experimental result files are not included in this repository.
