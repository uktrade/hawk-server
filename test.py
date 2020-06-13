from datetime import (
    datetime,
    timedelta,
)
import re
import unittest

from freezegun import (
    freeze_time,
)
import mohawk


from hawkserver import (
    authenticate_hawk_header,
)


class TestIntegration(unittest.TestCase):

    def test_bad_id_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('not-id', 'my-secret', url, 'GET', 'my-type', b'my-content')

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Unidentified id')
        self.assertEqual(creds, None)

    def test_bad_secret_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'not-secret', url, 'GET', 'my-type', b'my-content')

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Invalid mac')
        self.assertEqual(creds, None)

    def test_bad_method_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'GET', 'my-type', b'my-content')

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Invalid mac')
        self.assertEqual(creds, None)

    def test_bad_content_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'my-type', b'not-content')

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Invalid hash')
        self.assertEqual(creds, None)

    def test_bad_content_type_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'not-type', b'my-content')

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Invalid hash')
        self.assertEqual(creds, None)

    def test_time_skew_then_not_authenticated(self):
        url = 'http://127.0.0.1:8080/v1/'
        past = datetime.now() + timedelta(seconds=-61)
        with freeze_time(past):
            header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'my-type', b'my-content')

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Stale ts')
        self.assertEqual(creds, None)

    def test_seen_nonce_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header(
            'my-other-id', 'my-other-secret', url, 'POST', 'my-type', b'my-content')

        passed_nonce = None
        passed_id = None

        def seen_nonce_true(nonce, _id):
            nonlocal passed_nonce
            nonlocal passed_id
            passed_nonce = nonce
            passed_id = _id
            return True

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce_true, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Invalid nonce')
        self.assertEqual(creds, None)
        self.assertEqual(passed_id, 'my-other-id')
        self.assertEqual(passed_nonce, dict(re.findall(r'([a-z]+)="([^"]+)"', header))['nonce'])

    def test_invalid_header_format_then_not_authenticated(self):
        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            'Hawk d', 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Invalid header')
        self.assertEqual(creds, None)

    def test_invalid_ts_format_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'not-type', b'my-content')

        bad_auth_header = re.sub(r'ts="[^"]+"', 'ts="non-numeric"', header)
        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            bad_auth_header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Invalid ts')
        self.assertEqual(creds, None)

    def test_missing_nonce_then_not_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'not-type', b'my-content')

        bad_auth_header = re.sub(r', nonce="[^"]+"', '', header)
        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            bad_auth_header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, 'Missing nonce')
        self.assertEqual(creds, None)

    def test_correct_header_then_authenticated(self):
        url = 'http://my-domain:8080/v1/'
        header = hawk_auth_header('my-id', 'my-secret', url, 'POST', 'my-type', b'my-content')

        error, creds = authenticate_hawk_header(
            lookup_credentials, seen_nonce, 60,
            header, 'POST', 'my-domain', '8080', '/v1/', 'my-type', b'my-content',
        )
        self.assertEqual(error, None)
        self.assertEqual(creds, {
            'id': 'my-id',
            'key': 'my-secret',
        })


def hawk_auth_header(key_id, secret_key, url, method, content_type, content):
    return mohawk.Sender({
        'id': key_id,
        'key': secret_key,
        'algorithm': 'sha256',
    }, url, method, content_type=content_type, content=content).request_header


def seen_nonce(_, __):
    return False


def lookup_credentials(_id):
    return \
        {'id': 'my-id', 'key': 'my-secret'} if _id == 'my-id' else \
        {'id': 'my-other-id', 'key': 'my-other-secret'} if _id == 'my-other-id' else \
        None
