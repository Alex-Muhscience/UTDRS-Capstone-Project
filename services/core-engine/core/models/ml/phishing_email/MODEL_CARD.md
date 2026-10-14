# Phishing email model

The capstone's phishing classifier, as the core engine runs it. The ML detector uses it for every `email` event with enough text to judge.

| | |
|---|---|
| **Task** | Is this email phishing? Returns a probability from 0 to 1. |
| **Input** | The email's subject and body as one text. Lowercased and split into words of two or more characters; words outside the vocabulary are ignored. |
| **Model** | TF-IDF over 5,000 terms, into a feed-forward network: 256, 128 and 64 ReLU units, each followed by batch normalisation and dropout, then one sigmoid output. |
| **Trained by** | `research/capstone/models/train_phishing_model.py`: the recipe of the capstone's `phishing_model.py`, retrained so that the vectoriser is saved with the network. |
| **Training data** | The Kaggle *Phishing Email Dataset* (Naser Abdullah Alam): 82,486 emails drawn from Enron, Ling, CEAS 2008, Nazario, Nigerian Fraud and SpamAssassin. Cleaned and balanced to 78,466; 70% for training (a tenth of it to decide when to stop), 30% held out for testing. |
| **Files** | `weights.npz` (the network's weights) and `vocabulary.json` (the terms in input order, and their IDF weights). The engine runs them with NumPy: no TensorFlow and no pickle. |

## How well it performs

On the 23,540 held-out test emails, which played no part in training:

| | Accuracy | Precision | Recall | Legitimate emails flagged |
|---|---|---|---|---|
| Threshold 0.5 | 98.6% | 98.7% | 98.4% | 1.3% |
| **Threshold 0.7, what the engine uses** | 98.3% | 99.0% | 97.7% | 1.0% |

On the training emails it scores 99.6%. `metrics.json`, written by the training script, has the full figures.

## Why it was retrained

The capstone's `phishing_model.h5` (still in `research/capstone/models/`) cannot be used as it was saved: its fitted TF-IDF vectoriser went to a file that was never committed, and each of the network's inputs is one of that vectoriser's terms. Retraining with the same data, vectoriser and network gives a model whose vocabulary is known exactly. It also stops using the test emails to decide when to stop training, as the original did, so the test figures above are independent.

## What to keep in mind

- **The data is old and of one kind.** The emails are in English and mostly from 2008 and earlier: corporate mail, mailing lists, and the spam and fraud of that time. Expect it to do worse on current phishing, on other languages, and on mail unlike those sources. The figures above say how well it separates its own test set, not how it will do on your mail.
- **Its training text was already cleaned**: lowercased, with punctuation and common words removed. The engine gives it raw text, which the vocabulary absorbs in most cases (common words are simply not in it), but a web address arrives here as separate words where the training data had it run together.
- **Short emails are not sent to it.** With fewer than five known words the model answers with high confidence either way, so the detector falls back to its hand-written indicators.
- **It reads text only.** It does not see the sender, links' real destinations, attachments or headers.
