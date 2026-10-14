# Phishing email model

The capstone's phishing classifier, as the core engine runs it. The ML detector uses it for every `email` event with enough text to judge.

| | |
|---|---|
| **Task** | Is this email phishing? Returns a probability from 0 to 1. |
| **Input** | The email's subject and body as one text. Lowercased and split into words of two or more characters; words outside the vocabulary are ignored. |
| **Model** | TF-IDF over 5,000 terms, into a feed-forward network: 256, 128 and 64 ReLU units, each followed by batch normalisation, then one sigmoid output. |
| **Trained by** | `research/capstone/models/phishing_model.py`, saved as `phishing_model.h5` (Keras 3.7). |
| **Training data** | The Kaggle *Phishing Email Dataset* (Naser Abdullah Alam): 82,486 emails drawn from Enron, Ling, CEAS 2008, Nazario, Nigerian Fraud and SpamAssassin. Balanced to 78,466, with 70% for training. |
| **Files** | `weights.npz` (the network's weights, float32) and `vocabulary.json` (the terms in input order, and their IDF weights). No TensorFlow and no pickle. |

## How well it performs

Measured with `research/capstone/models/export_phishing_model.py`, which writes these files, on the same split the training script made:

| Split | Emails | Accuracy | Precision | Recall | False positives |
|---|---|---|---|---|---|
| Test (30%, not trained on) | 23,540 | 98.2% | 98.3% | 98.2% | 1.8% of legitimate emails |
| Training (70%) | 54,926 | 99.4% | 99.4% | 99.4% | 0.7% |

The engine raises an alert above 0.7, where the test split gives 98.8% precision, 97.6% recall, and 1.2% of legitimate emails flagged.

## What to keep in mind

- **The vocabulary was reconstructed.** The training script saved the fitted vectoriser to a file that was never committed. Refitting it reproduces all but a few terms, but because terms are numbered alphabetically, a few differences put long stretches of the vocabulary one position out of step, and the model scored 75%. The export script records the corrections that restore the alignment and explains how they were found. The alignment is confirmed by the results above; at the edges of each corrected stretch, a handful of the 5,000 inputs may carry a neighbouring term.
- **The data is old and of one kind.** The emails are in English and mostly from 2008 and earlier: corporate mail, mailing lists, and the spam and fraud of that time. Expect it to do worse on current phishing, on other languages, and on mail unlike those sources. The figures above say how well it separates its own test set, not how it will do on your mail.
- **Its training text was already cleaned**: lowercased, with punctuation and common words removed. The engine gives it raw text, which the vocabulary absorbs in most cases (common words are simply not in it), but a web address arrives here as separate words where the training data had it run together.
- **Short emails are not sent to it.** With fewer than five known words the model answers with high confidence either way, so the detector falls back to its hand-written indicators.
- **It reads text only.** It does not see the sender, links' real destinations, attachments or headers.
