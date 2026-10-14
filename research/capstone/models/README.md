# Capstone models

The capstone's trained models, and the scripts that train the versions the core engine runs.

| File | What it is |
|---|---|
| `phishing_model.py`, `phishing_model.h5` | The original phishing email classifier and its training script. The model cannot be used as saved: its fitted TF-IDF vectoriser was never committed. |
| `train_phishing_model.py` | The same recipe, retrained with the vectoriser saved. Writes the files the engine uses ([model card](../../../services/core-engine/core/models/ml/phishing_email/MODEL_CARD.md)). |
| `advanced_threat_detection_model.h5` | The original network threat model (a CNN-LSTM, 21 inputs, 10 classes). It cannot be used: its training script was empty, and its features, scaling and classes were not recorded. |
| `train_network_threat_model.py` | A model of the same architecture trained from scratch on UNSW-NB15, with all of that written down ([model card](../../../services/core-engine/core/models/ml/network_threat/MODEL_CARD.md)). |

Each training script takes the dataset's location and an output directory, and documents where to get the data. Both datasets are public; neither is stored here.
