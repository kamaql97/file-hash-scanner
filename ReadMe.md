# Palo Alto Networks Home Task
Code written by **Kamal Qarain** in **December 2020**


## Setup
1. [Get a VirusTotal API key](https://developers.virustotal.com/v3.0/reference#getting-started) (if you do not already have one)
1. Define a new environmental variable `VIRUSTOTAL_API_KEY` on your machine and set your API key as its value
1. Make sure you have the Python `requests` module installed, run the command:

```bash
pip install -r requirements.txt 
```

_Note that code was written and tested on **Python 3.8.5**. Using a different Python interpreter may result in the code not working as expected!_


## Usage
Use the `request_data` method with the following arguments:
1. String represting the file's hash (MD5, SHA-1, SHA-256)
1. (Optional) VirusTotal API key as a string if not stored in your environmental variables.

The function prints the API response message and returns the scan results (if the file could be scanned).

##### example.py
```python
from solution.scanner import request_data

with open('output.md', 'w+') as output_file:
    output_file.write(request_data('84c82835a5d21bbcf75a61706d8ab549'))
```

## Feedback
Your feedback is greatly appreciated. If you have any ideas or suggestions, [send me an email](mailto:kamalq97@gmail.com). 
