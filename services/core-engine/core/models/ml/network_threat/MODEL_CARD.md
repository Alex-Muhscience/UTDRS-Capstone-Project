# Network threat model

Judges one network flow: normal traffic, or one of nine kinds of attack. The ML detector uses it for `network`, `traffic` and `dns` events that carry a flow record with all 21 measurements below.

| | |
|---|---|
| **Task** | Which of 10 classes is this flow? Normal, Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode or Worms. |
| **Input** | 21 measurements of one flow, under their UNSW-NB15 (Argus) names: `dur`, `spkts`, `dpkts`, `sbytes`, `dbytes`, `rate`, `sload`, `dload`, `sloss`, `dloss`, `sinpkt`, `dinpkt`, `sjit`, `djit`, `swin`, `dwin`, `tcprtt`, `synack`, `ackdat`, `smean`, `dmean`. Each is log-scaled and standardised with the training data's mean and spread (`features.json`). |
| **Model** | A CNN-LSTM, the architecture of the capstone's `advanced_threat_detection_model.h5`: two 1-D convolutions (64 and 128 filters, each followed by pooling), two LSTM layers of 128 units, a 256-unit dense layer and a 10-way softmax. |
| **Trained by** | `research/capstone/models/train_network_threat_model.py`. |
| **Training data** | UNSW-NB15 (Moustafa and Slay, 2015; UNSW Canberra): the official training partition of 175,341 flows (a tenth of it to decide when to stop), tested on the separate partition of 82,332 flows. |
| **Files** | `weights.npz`, `features.json` (the features, classes and scaling) and `reference.npz` (50 test flows with Keras' outputs, which the tests check the NumPy implementation against). The engine runs it with NumPy: no TensorFlow. |

## How well it performs

The question that matters most is whether a flow is an attack at all. The detector raises an alert only when the model puts the chance of an attack above 0.95. On the 82,332 test flows:

| Alert when the chance of an attack is above | Normal flows flagged | Attacks caught | Alerts that are real attacks |
|---|---|---|---|
| 0.5 | 39.9% | 99.4% | 75.3% |
| 0.9 | 2.2% | 83.8% | 97.9% |
| **0.95, what the engine uses** | 0.65% | 80.2% | 99.3% |
| 0.99 | 0.32% | 75.0% | 99.7% |

When it catches an attack, it names the right kind 80% of the time. Some kinds it rarely catches at 0.9: Fuzzers (31%), Shellcode (35%) and Worms (43%). Generic (99%), Backdoor (95%), Analysis (91%), Reconnaissance (87%), DoS (87%) and Exploits (86%) fare better. Told apart by most likely class alone, it is right on 74% of test flows; `metrics.json` has the figures per class.

## Why it was rebuilt

The capstone's `advanced_threat_detection_model.h5` (still in `research/capstone/models/`) has this architecture, but its training script was empty and nothing recorded its 21 input features, how they were scaled, or what its 10 classes were, so its output cannot be read. This model is trained from scratch on a public dataset with 10 classes, with all of that written down.

## What to keep in mind

- **It needs flow records.** The measurements come from a flow sensor such as Argus, or Zeek with the fields mapped to these names. The gateway's events do not carry them unless a source sends them, in the event's `raw_data` either at the top level or under `flow`. Without them the detector uses its hand-written indicators.
- **Lab traffic.** UNSW-NB15 was generated in a test bed in 2015. Real networks look different, and the two partitions of the dataset already differ enough that the threshold has to be high to keep false alarms down. Expect more false alarms, and fewer catches, on your own traffic.
- **Left out on purpose:** the IP time-to-live fields (`sttl`, `dttl`, `ct_state_ttl`), which separate attacks in this dataset because of how the test bed was built rather than because of the attacks; the `ct_*` counters, which describe a window of earlier connections the engine does not see; and the protocol, service and state categories.
- **The categories are broad.** The MITRE ATT&CK techniques the detector attaches (in `ml_detector.py`) are the closest matches, not exact ones.
