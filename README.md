# hawk-server

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

is_authenticated, error_message, credentials = authenticate_hawk_header(
    lookup_credentials, seen_nonce, max_skew,
    header, method, host, port, path, content_type, content,
)
if not is_authenticated:
    # Return error or raise exception as needed
```