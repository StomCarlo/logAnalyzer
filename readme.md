# Unsupervised Outlier Detection from web server logs

This repository contains a set of funcions to preprocess web server logs and the implementation of an unsupervised outlier detection method.

In the folder fingerprints a set of attack fingerprints are described. They are used to implement a set of heuristics to prefilter the logs.
While the file utilities.py contains a set of simple function to load the datasets.
The core of this work is in webServerLogs.py, where all the funcions to preprocess the data, apply the proposed ML model and evaluate it are defined.
Lastly examples.py contains a set of examples of the usage of these funcions.