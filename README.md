# hawk-server [![CircleCI](https://circleci.com/gh/uktrade/hawk-server.svg?style=shield)](https://circleci.com/gh/uktrade/hawk-server) [![Test Coverage](https://api.codeclimate.com/v1/badges/8bc445ea9d471b133b3f/test_coverage)](https://codeclimate.com/github/uktrade/hawk-server/test_coverage)

Utility function to perform the server-side of Hawk authentication


## Installation

```bash
pip install hawk-server
```


## Usage

```python
from hawkserver import authenticate_hawk_header

def lookup_credentials(id):
    # Return {'id': 'some-id', 'key': 'some-secret'} matching credentials,
    # or None if credentials can't be found

def seen_nonce(nonce, id):
    # Store nonce, return True if nonce previously seen

error_message, credentials = authenticate_hawk_header(
    lookup_credentials, seen_nonce, max_skew,
    header, method, host, port, path, content_type, content,
)
if error_message is not None:
    # Return error or raise exception as needed
```
