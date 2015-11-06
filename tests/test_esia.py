import os
import copy
import base64
import datetime
import tempfile
from calendar import timegm
from unittest import TestCase
from unittest.mock import patch, create_autospec

import httpretty
import jwt
import pytz

from esia_connector.client import EsiaSettings, EsiaAuth, EsiaInformationConnector
from esia_connector.exceptions import IncorrectJsonError, HttpError, IncorrectMarkerError
from esia_connector.utils import get_timestamp, sign_params, make_request
from tests.utils import SameDict


TEST_SETTINGS = EsiaSettings(esia_client_id='TEST_CLIENT_ID',
                             redirect_uri='http://localhost:8000/handle_esia_code',
                             certificate_file=os.path.join(os.path.dirname(__file__), 'res', 'test.crt'),
                             private_key_file=os.path.join(os.path.dirname(__file__), 'res', 'test.key'),
                             esia_service_url='https://esia-portal1.test.gosuslugi.ru',
                             esia_scope='openid http://esia.gosuslugi.ru/usr_inf')


class GetTimestampTests(TestCase):
    @patch('esia_connector.utils.datetime')
    def test(self, datetime_mock):

        datetime_mock.datetime.now.return_value = datetime.datetime(2015, 11, 2, 9, 52, 36, 615866, tzinfo=pytz.utc)

        result = get_timestamp()

        expected_result = '2015.11.02 09:52:36 +0000'

        self.assertEqual(result, expected_result)


class SignParamsTests(TestCase):
    maxDiff = None

    def test_sign_params(self):

        scope = 'openid http://esia.gosuslugi.ru/usr_inf'
        timestamp = '2015.11.02 09:37:16 +0000'
        client_id = 'YOURID'
        state = 'f918e3be-664e-45db-b5a2-adbf5d6ae3f6'

        params = {
            'redirect_uri': 'http://your-service.ru/redirect_handler',
            'access_type': 'offline',
            'state': state,
            'scope': scope,
            'response_type': 'code',
            'client_id': client_id,
            'timestamp': timestamp,
        }

        signed_params = sign_params(params,
                                    certificate_file=TEST_SETTINGS.certificate_file,
                                    private_key_file=TEST_SETTINGS.private_key_file)

        self.assertIn('client_secret', signed_params)

        signature = signed_params['client_secret']

        message = ''.join([scope, timestamp, client_id, state])

        def write_to_temp_file(content):
            """
            Writes content to temp file and returns file name
            :param content: binary content
            :return: file path
            """
            temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
            temp_file.write(content)
            temp_file.close()
            return temp_file.name

        message_path = write_to_temp_file(message.encode())

        try:
            encoded_signature = base64.urlsafe_b64decode(signature)
        except Exception as e:
            self.fail("client_id is not urlsafe base64 encoded string! (Exc: %s)" % e)

        signature_path = write_to_temp_file(encoded_signature)

        verify_cmd_tpl = "openssl smime -verify -inform DER -in {sig} -content {cnt} -noverify  -certfile {cert_file}"
        verify_cmd = verify_cmd_tpl.format(
            sig=signature_path,
            cnt=message_path,
            cert_file=TEST_SETTINGS.certificate_file
        )
        print(verify_cmd)
        res = os.system(verify_cmd)
        self.assertEqual(res, 0, "Signature verification failed!")


class MakeRequestTests(TestCase):
    def setUp(self):
        self.url = "https://esia.gosuslugi.ru/some/url"

    @httpretty.activate
    def test_ok(self):
        httpretty.register_uri(method=httpretty.POST,
                               uri=self.url,
                               body=b'{"correct_json": true}')
        result = make_request(url=self.url, method='POST')
        expected_result = {'correct_json': True}
        self.assertDictEqual(result, expected_result)

    @httpretty.activate
    def test_http_error(self):
        httpretty.register_uri(method=httpretty.GET,
                               uri=self.url,
                               status=400)
        self.assertRaises(HttpError, make_request, url=self.url)

    @httpretty.activate
    def test_not_valid_json(self):
        httpretty.register_uri(method=httpretty.GET,
                               uri=self.url,
                               body=b':( :(')
        self.assertRaises(IncorrectJsonError, make_request, url=self.url)


class EsiaAuthConnectorTests(TestCase):

    def setUp(self):
        self.maxDiff = None

        self.auth_url_params = {
            'client_id': TEST_SETTINGS.esia_client_id,
            'client_secret': '',
            'redirect_uri': TEST_SETTINGS.redirect_uri,
            'scope': TEST_SETTINGS.esia_scope,
            'response_type': 'code',
            'access_type': 'offline'
        }

        self.esia_auth = EsiaAuth(TEST_SETTINGS)

    @patch('esia_connector.client.sign_params', autospec=True)
    @patch('esia_connector.client.get_timestamp', autospec=True)
    def test_get_auth_url_state_provided(self, get_timestamp_mock, sign_params_mock):

        expected_timestamp = '2015.11.02 09:37:16 +0000'

        unsigned_params = copy.copy(self.auth_url_params)
        unsigned_params.update({
            'timestamp': expected_timestamp,
            'state': 'SOME-STATE',
        })

        signed_params = copy.copy(unsigned_params)
        signed_params.update({'client_secret': 'SECRET'})

        get_timestamp_mock.return_value = expected_timestamp
        sign_params_mock.return_value = signed_params

        url = self.esia_auth.get_auth_url(state='SOME-STATE')

        expected_url = 'https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac?access_type=offline&client_id=TEST_CLIENT_ID&client_secret=SECRET&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fhandle_esia_code&response_type=code&scope=openid+http%3A%2F%2Fesia.gosuslugi.ru%2Fusr_inf&state=SOME-STATE&timestamp=2015.11.02+09%3A37%3A16+%2B0000'
        self.assertEqual(url, expected_url)

        get_timestamp_mock.assert_called_once_with()

        sign_params_mock.assert_called_once_with(SameDict(unsigned_params),
                                                 certificate_file=TEST_SETTINGS.certificate_file,
                                                 private_key_file=TEST_SETTINGS.private_key_file)

    @patch('esia_connector.client.uuid', autospec=True)
    @patch('esia_connector.client.sign_params', autospec=True)
    @patch('esia_connector.client.get_timestamp', autospec=True)
    def test_get_auth_url_state_auto_generated(self, get_timestamp_mock, sign_params_mock, uuid_mock):
        expected_timestamp = '2015.11.02 09:37:16 +0000'

        expected_state = 'SOME-STATE'

        uuid_mock.uuid4.return_value = expected_state

        unsigned_params = copy.copy(self.auth_url_params)
        unsigned_params.update({
            'timestamp': expected_timestamp,
            'state': expected_state,
        })

        signed_params = copy.copy(unsigned_params)
        signed_params.update({'client_secret': 'SECRET'})

        get_timestamp_mock.return_value = expected_timestamp
        sign_params_mock.return_value = signed_params

        url = self.esia_auth.get_auth_url()

        expected_url = 'https://esia-portal1.test.gosuslugi.ru/aas/oauth2/ac?access_type=offline&client_id=TEST_CLIENT_ID&client_secret=SECRET&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fhandle_esia_code&response_type=code&scope=openid+http%3A%2F%2Fesia.gosuslugi.ru%2Fusr_inf&state=SOME-STATE&timestamp=2015.11.02+09%3A37%3A16+%2B0000'
        self.assertEqual(url, expected_url)

        get_timestamp_mock.assert_called_once_with()
        uuid_mock.uuid4.assert_called_once_with()

        sign_params_mock.assert_called_once_with(SameDict(unsigned_params),
                                                 certificate_file=TEST_SETTINGS.certificate_file,
                                                 private_key_file=TEST_SETTINGS.private_key_file)

    @patch('esia_connector.client.make_request', autospec=True)
    @patch('esia_connector.client.sign_params', autospec=True)
    @patch('esia_connector.client.get_timestamp', autospec=True)
    def test_complete_authorization_ok_without_validation(self, get_timestamp_mock, sign_params_mock, make_request_mock):

        expected_oid = 1000323031
        expected_token = 'eyJhbGciOiJSUzI1NiIsInNidCI6ImFjY2VzcyIsInR5cCI6IkpXVCIsInZlciI6MX0.eyJleHAiOjE0NDY1MDM1MDQsInNjb3BlIjoiaHR0cDpcL1wvZXNpYS5nb3N1c2x1Z2kucnVcL3Vzcl9pbmY_b2lkPTEwMDAzMjMwMzEgb3BlbmlkIiwiaXNzIjoiaHR0cDpcL1wvZXNpYS5nb3N1c2x1Z2kucnVcLyIsIm5iZiI6MTQ0NjQ5OTkwNCwidXJuOmVzaWE6c2lkIjoiMDQ2MzZjNTVlY2FhYTJjYjc4NGM5NjhmZjJjMzE4NTlmODVjM2JmM2IyY2UxYTI4MzM0YjlhYjI4YzczMjk3OCIsInVybjplc2lhOnNial9pZCI6MTAwMDMyMzAzMSwiY2xpZW50X2lkIjoiU0VQQ0FQIiwiaWF0IjoxNDQ2NDk5OTA0fQ.LYBJTAj1mOI6Ldq7HInyi8IBN1o37McL9b8Z1b6GukaYliPNPNAZ6TVxpdn4BGdFuDtbNsKLe7bJvA0KHkVbKxNE73ZrLaI8mK9uOYVdgYxyOhKrzJ3pZee3Tzu19itTqdBLS_IRLjXj3jX4HLRCIRey09lS4AoYplB6GnZQX39XgPKNFSkP059ImA6tX-MJfQ_ZnbCdcIpm_i6YG6M1qbg4S9f1ArksDtuS6gzW7Ody-AAI31lDWXScycQDZ49TRNbJ23F2wY5Ws-bZkbKzUUF2JdokEgPJuWLw7GAX3IwUOrleVA57rR7Oc8P29xBt0RjFr57NfLn8TmFoziWyZw'

        expected_response_data = {
            "state": "b7062082-5493-409b-b51b-c7f788136a1c",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "bb35e3ef-7da7-4300-bddb-4e0d4972345b",
            "id_token": "TOKENDATA",
            "access_token": expected_token,
        }
        make_request_mock.return_value = expected_response_data

        expected_timestamp = '2015.11.02 09:37:16 +0000'

        get_timestamp_mock.return_value = expected_timestamp

        code = 'eyJhbGciOiJSUzI1NiIsInNidCI6ImF1dGhvcml6YXRpb25fY29kZSIsInR5cCI6IkpXVCIsInZlciI6MX0.eyJhdXRoX3RpbWUiOjE0NDY0OTk3NTY2MDMsImF1dGhfbXRoZCI6IlBXRCIsImV4cCI6MTQ0Nzk0NjMxOTU5NCwic2NvcGUiOiJodHRwOlwvXC9lc2lhLmdvc3VzbHVnaS5ydVwvdXNyX2luZj9vaWQ9MTAwMDMyMzAzMSBvcGVuaWQiLCJpc3MiOiJodHRwOlwvXC9lc2lhLmdvc3VzbHVnaS5ydVwvIiwibmJmIjoxNDQ2NDk5NzU5LCJ1cm46ZXNpYTpjbGllbnQ6c3RhdGUiOiJiNzA2MjA4Mi01NDkzLTQwOWItYjUxYi1jN2Y3ODgxMzZhMWMiLCJ1cm46ZXNpYTpzaWQiOiIwNDYzNmM1NWVjYWFhMmNiNzg0Yzk2OGZmMmMzMTg1OWY4NWMzYmYzYjJjZTFhMjgzMzRiOWFiMjhjNzMyOTc4IiwicGFyYW1zIjp7InJlbW90ZV9pcCI6Ijk1LjI3LjgzLjEzOCIsInVzZXJfYWdlbnQiOiJNb3ppbGxhXC81LjAgKFgxMTsgTGludXggeDg2XzY0KSBBcHBsZVdlYktpdFwvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lXC80Ni4wLjI0OTAuODAgU2FmYXJpXC81MzcuMzYifSwidXJuOmVzaWE6c2JqIjp7InVybjplc2lhOnNiajplaWQiOjc0Mzc4NDgsInVybjplc2lhOnNiajpuYW0iOiJPSUQuMTAwMDMyMzAzMSIsInVybjplc2lhOnNiajpvaWQiOjEwMDAzMjMwMzEsInVybjplc2lhOnNiajp0eXAiOiJQIn0sImNsaWVudF9pZCI6IlNFUENBUCIsImlhdCI6MTQ0NjQ5OTc1OX0.Usz6bANHcdRsx4Pg_eqbaNsa9NmpXpUasx5NBakV1crnwo-nEsau19a0mvMVNr6QrS8vqcPEgfQCUecBjxCrcOlVl2qKpYlIYySLtWyCFgBHvuM9vsJBUPeIcKD3Ta_IFoDbofzHbzqJ61wB2Ckqf_erpo08BqVxiT3ZxuRv4iIozNJxgXLHHWbDGVQ6wymsUhiTIGcNfJhrItHtsyKhVlpAnwtY-I9Jm0YkRNe6pGkHdrGyVFClMmV8-HkkFZq6VBHpPqkcK1hl_cMQdHMqEhySuw1oojOrTC-0jZNjuzSacJHXVmrpI4k7F3rDorlziflBpx00m88ox4lA6BAfmw'
        state = 'b7062082-5493-409b-b51b-c7f788136a1c'

        unsigned_params = {
            'client_id': TEST_SETTINGS.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': TEST_SETTINGS.redirect_uri,
            'timestamp': expected_timestamp,
            'token_type': 'Bearer',
            'scope': TEST_SETTINGS.esia_scope,
            'state': state,
        }
        signed_params = copy.copy(unsigned_params)
        signed_params.update({'client_secret': 'SECRET'})

        sign_params_mock.return_value = signed_params

        esia_auth = EsiaAuth(TEST_SETTINGS)
        parse_token_mock = create_autospec(esia_auth._parse_token)
        parse_token_mock.return_value = {'urn:esia:sbj': {'urn:esia:sbj:oid': expected_oid}}
        esia_auth._parse_token = parse_token_mock
        validate_token_mock = create_autospec(esia_auth._validate_token)
        esia_auth._validate_token = validate_token_mock

        result = esia_auth.complete_authorization(code, state, validate_token=False)

        self.assertIsInstance(result, EsiaInformationConnector)
        self.assertEqual(result.oid, expected_oid)
        self.assertEqual(result.token, expected_token)
        self.assertEqual(result.settings, esia_auth.settings)

        get_timestamp_mock.assert_called_once_with()
        sign_params_mock.assert_called_once_with(SameDict(unsigned_params),
                                                 certificate_file=TEST_SETTINGS.certificate_file,
                                                 private_key_file=TEST_SETTINGS.private_key_file)

        make_request_mock.assert_called_once_with(url="{0}{1}".format(TEST_SETTINGS.esia_service_url,
                                                                      EsiaAuth._TOKEN_EXCHANGE_URL),
                                                  method='POST',
                                                  data=signed_params)
        parse_token_mock.assert_called_once_with('TOKENDATA')
        self.assertFalse(validate_token_mock.called)

    @patch('esia_connector.client.make_request', autospec=True)
    @patch('esia_connector.client.sign_params', autospec=True)
    @patch('esia_connector.client.get_timestamp', autospec=True)
    def test_complete_authorization_ok_with_validation(self, get_timestamp_mock, sign_params_mock, make_request_mock):

        expected_oid = 1000323031
        expected_token = 'eyJhbGciOiJSUzI1NiIsInNidCI6ImFjY2VzcyIsInR5cCI6IkpXVCIsInZlciI6MX0.eyJleHAiOjE0NDY1MDM1MDQsInNjb3BlIjoiaHR0cDpcL1wvZXNpYS5nb3N1c2x1Z2kucnVcL3Vzcl9pbmY_b2lkPTEwMDAzMjMwMzEgb3BlbmlkIiwiaXNzIjoiaHR0cDpcL1wvZXNpYS5nb3N1c2x1Z2kucnVcLyIsIm5iZiI6MTQ0NjQ5OTkwNCwidXJuOmVzaWE6c2lkIjoiMDQ2MzZjNTVlY2FhYTJjYjc4NGM5NjhmZjJjMzE4NTlmODVjM2JmM2IyY2UxYTI4MzM0YjlhYjI4YzczMjk3OCIsInVybjplc2lhOnNial9pZCI6MTAwMDMyMzAzMSwiY2xpZW50X2lkIjoiU0VQQ0FQIiwiaWF0IjoxNDQ2NDk5OTA0fQ.LYBJTAj1mOI6Ldq7HInyi8IBN1o37McL9b8Z1b6GukaYliPNPNAZ6TVxpdn4BGdFuDtbNsKLe7bJvA0KHkVbKxNE73ZrLaI8mK9uOYVdgYxyOhKrzJ3pZee3Tzu19itTqdBLS_IRLjXj3jX4HLRCIRey09lS4AoYplB6GnZQX39XgPKNFSkP059ImA6tX-MJfQ_ZnbCdcIpm_i6YG6M1qbg4S9f1ArksDtuS6gzW7Ody-AAI31lDWXScycQDZ49TRNbJ23F2wY5Ws-bZkbKzUUF2JdokEgPJuWLw7GAX3IwUOrleVA57rR7Oc8P29xBt0RjFr57NfLn8TmFoziWyZw'

        expected_response_data = {
            "state": "b7062082-5493-409b-b51b-c7f788136a1c",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "bb35e3ef-7da7-4300-bddb-4e0d4972345b",
            "id_token": "TOKENDATA",
            "access_token": expected_token,
        }
        make_request_mock.return_value = expected_response_data

        expected_timestamp = '2015.11.02 09:37:16 +0000'

        get_timestamp_mock.return_value = expected_timestamp

        code = 'eyJhbGciOiJSUzI1NiIsInNidCI6ImF1dGhvcml6YXRpb25fY29kZSIsInR5cCI6IkpXVCIsInZlciI6MX0.eyJhdXRoX3RpbWUiOjE0NDY0OTk3NTY2MDMsImF1dGhfbXRoZCI6IlBXRCIsImV4cCI6MTQ0Nzk0NjMxOTU5NCwic2NvcGUiOiJodHRwOlwvXC9lc2lhLmdvc3VzbHVnaS5ydVwvdXNyX2luZj9vaWQ9MTAwMDMyMzAzMSBvcGVuaWQiLCJpc3MiOiJodHRwOlwvXC9lc2lhLmdvc3VzbHVnaS5ydVwvIiwibmJmIjoxNDQ2NDk5NzU5LCJ1cm46ZXNpYTpjbGllbnQ6c3RhdGUiOiJiNzA2MjA4Mi01NDkzLTQwOWItYjUxYi1jN2Y3ODgxMzZhMWMiLCJ1cm46ZXNpYTpzaWQiOiIwNDYzNmM1NWVjYWFhMmNiNzg0Yzk2OGZmMmMzMTg1OWY4NWMzYmYzYjJjZTFhMjgzMzRiOWFiMjhjNzMyOTc4IiwicGFyYW1zIjp7InJlbW90ZV9pcCI6Ijk1LjI3LjgzLjEzOCIsInVzZXJfYWdlbnQiOiJNb3ppbGxhXC81LjAgKFgxMTsgTGludXggeDg2XzY0KSBBcHBsZVdlYktpdFwvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lXC80Ni4wLjI0OTAuODAgU2FmYXJpXC81MzcuMzYifSwidXJuOmVzaWE6c2JqIjp7InVybjplc2lhOnNiajplaWQiOjc0Mzc4NDgsInVybjplc2lhOnNiajpuYW0iOiJPSUQuMTAwMDMyMzAzMSIsInVybjplc2lhOnNiajpvaWQiOjEwMDAzMjMwMzEsInVybjplc2lhOnNiajp0eXAiOiJQIn0sImNsaWVudF9pZCI6IlNFUENBUCIsImlhdCI6MTQ0NjQ5OTc1OX0.Usz6bANHcdRsx4Pg_eqbaNsa9NmpXpUasx5NBakV1crnwo-nEsau19a0mvMVNr6QrS8vqcPEgfQCUecBjxCrcOlVl2qKpYlIYySLtWyCFgBHvuM9vsJBUPeIcKD3Ta_IFoDbofzHbzqJ61wB2Ckqf_erpo08BqVxiT3ZxuRv4iIozNJxgXLHHWbDGVQ6wymsUhiTIGcNfJhrItHtsyKhVlpAnwtY-I9Jm0YkRNe6pGkHdrGyVFClMmV8-HkkFZq6VBHpPqkcK1hl_cMQdHMqEhySuw1oojOrTC-0jZNjuzSacJHXVmrpI4k7F3rDorlziflBpx00m88ox4lA6BAfmw'
        state = 'b7062082-5493-409b-b51b-c7f788136a1c'

        unsigned_params = {
            'client_id': TEST_SETTINGS.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': TEST_SETTINGS.redirect_uri,
            'timestamp': expected_timestamp,
            'token_type': 'Bearer',
            'scope': TEST_SETTINGS.esia_scope,
            'state': state,
        }
        signed_params = copy.copy(unsigned_params)
        signed_params.update({'client_secret': 'SECRET'})

        sign_params_mock.return_value = signed_params

        esia_auth = EsiaAuth(TEST_SETTINGS)
        parse_token_mock = create_autospec(esia_auth._parse_token)
        esia_auth._parse_token = parse_token_mock
        validate_token_mock = create_autospec(esia_auth._validate_token)
        validate_token_mock.return_value = {'urn:esia:sbj': {'urn:esia:sbj:oid': expected_oid}}
        esia_auth._validate_token = validate_token_mock

        result = esia_auth.complete_authorization(code, state, validate_token=True)

        self.assertIsInstance(result, EsiaInformationConnector)
        self.assertEqual(result.oid, expected_oid)
        self.assertEqual(result.token, expected_token)
        self.assertEqual(result.settings, esia_auth.settings)

        get_timestamp_mock.assert_called_once_with()
        sign_params_mock.assert_called_once_with(SameDict(unsigned_params),
                                                 certificate_file=TEST_SETTINGS.certificate_file,
                                                 private_key_file=TEST_SETTINGS.private_key_file)

        make_request_mock.assert_called_once_with(url="{0}{1}".format(TEST_SETTINGS.esia_service_url,
                                                                      EsiaAuth._TOKEN_EXCHANGE_URL),
                                                  method='POST',
                                                  data=signed_params)
        validate_token_mock.assert_called_once_with('TOKENDATA')
        self.assertFalse(parse_token_mock.called)

    def test_validate_token_no_key(self):

        token = ''

        settings = copy.copy(TEST_SETTINGS)
        settings.esia_token_check_key = None
        esia_auth = EsiaAuth(settings)

        self.assertRaises(ValueError, esia_auth._validate_token, token)

    def get_token_payload(self, **content):
        timestamp_now = timegm(datetime.datetime.utcnow().utctimetuple())

        payload = {
            'amr': 'PWD',
            'aud': 'TEST_CLIENT_ID',
            'auth_time': timestamp_now - 2,
            'exp': timestamp_now + 100,
            'iat': timestamp_now,
            'iss': 'http://esia.gosuslugi.ru/',
            'nbf': 1447060287,
            'sub': 1000323031,
            'urn:esia:amd': 'PWD',
            'urn:esia:sbj': {
                'urn:esia:sbj:nam': 'OID.1000323031',
                'urn:esia:sbj:oid': 1000323031,
                'urn:esia:sbj:typ': 'P'
            },
            'urn:esia:sid': '5e17c68315126b257663b10aef5cc9e5c3bf7ae5a903bf91bd3f34b8373ce4b9'
        }
        payload.update(content)
        return payload

    def test_validate_token_incorrect_issuer(self):

        token_payload = self.get_token_payload(iss='https://ya.ru')

        with open(TEST_SETTINGS.private_key_file, 'r') as f:
            data = f.read()

        token = jwt.encode(token_payload, key=data)

        settings = copy.copy(TEST_SETTINGS)
        settings.esia_token_check_key = settings.private_key_file
        esia_auth = EsiaAuth(settings)

        self.assertRaises(IncorrectMarkerError, esia_auth._validate_token, token)

    def test_validate_token_incorrect_audience(self):

        token_payload = self.get_token_payload(aud='BOO')

        with open(TEST_SETTINGS.private_key_file, 'r') as f:
            data = f.read()

        token = jwt.encode(token_payload, key=data)

        settings = copy.copy(TEST_SETTINGS)
        settings.esia_token_check_key = settings.private_key_file
        esia_auth = EsiaAuth(settings)

        self.assertRaises(IncorrectMarkerError, esia_auth._validate_token, token)

    def test_validate_token_ok(self):

        token_payload = self.get_token_payload()

        with open(TEST_SETTINGS.private_key_file, 'r') as f:
            key_data = f.read()

        token = jwt.encode(token_payload, key=key_data)

        settings = copy.copy(TEST_SETTINGS)
        settings.esia_token_check_key = settings.private_key_file
        esia_auth = EsiaAuth(settings)

        result = esia_auth._validate_token(token)

        self.assertDictEqual(result, token_payload)


class EsiaInformationConnectorTests(TestCase):
    def setUp(self):
        super().setUp()
        self.maxDiff = None
        self.simple_expected_result = {'result': 'result'}
        self.expected_simple_endpoint = '/some/endpoint'

        self.connector = EsiaInformationConnector(access_token='', oid=1, settings=TEST_SETTINGS)

    @httpretty.activate
    def test_get_person_main_info(self):
        main_body = b'{"stateFacts":["EntityRoot"],"eTag":"0E3A9A5850B4700A791677B9441604FD29AD2B0B","firstName":"\xd0\x98\xd0\xbc\xd1\x8f006","lastName":"\xd0\xa4\xd0\xb0\xd0\xbc\xd0\xb8\xd0\xbb\xd0\xb8\xd1\x8f006","middleName":"\xd0\x9e\xd1\x82\xd1\x87\xd0\xb5\xd1\x81\xd1\x82\xd0\xb2\xd0\xbe006","birthDate":"07.06.1994","gender":"M","trusted":true,"citizenship":"RUS","snils":"000-000-600 06","updatedOn":1446118560,"status":"REGISTERED","birthPlace":"! \xd0\x9d\xd0\xb8\xd0\xba\xd0\xb0\xd0\xba\xd0\xb8\xd0\xb5 \xd0\xb4\xd0\xb0\xd0\xbd\xd0\xbd\xd1\x8b\xd0\xb5 \xd0\xa3\xd0\x97 \xd0\xbd\xd0\xb5 \xd0\xbc\xd0\xb5\xd0\xbd\xd1\x8f\xd1\x82\xd1\x8c ! \xd0\x9e\xd0\xb1\xd1\x89\xd0\xb0\xd1\x8f \xd1\x82\xd0\xb5\xd1\x81\xd1\x82\xd0\xbe\xd0\xb2\xd0\xb0\xd1\x8f \xd0\xa3\xd0\x97"}'
        httpretty.register_uri(method=httpretty.GET,
                               uri="%s/prns/1" % self.connector._rest_base_url,
                               body=main_body)

        result = self.connector.get_person_main_info()

        expected = {
            'birthDate': '07.06.1994',
            'birthPlace': '! Никакие данные УЗ не менять ! Общая тестовая УЗ',
            'citizenship': 'RUS',
            'eTag': '0E3A9A5850B4700A791677B9441604FD29AD2B0B',
            'firstName': 'Имя006',
            'gender': 'M',
            'lastName': 'Фамилия006',
            'middleName': 'Отчество006',
            'snils': '000-000-600 06',
            'stateFacts': ['EntityRoot'],
            'status': 'REGISTERED',
            'trusted': True,
            'updatedOn': 1446118560
        }

        self.assertDictEqual(result, expected)

    @httpretty.activate
    def test_get_person_addresses(self):

        addresses_body = b'{"stateFacts":["hasSize"],"size":2,"eTag":"EDAD381930198EC96479BAE44FA16D3FFE68BB06","elements":[{"stateFacts":["Identifiable"],"eTag":"C3CB5C9959AFFB7F7415B9E14CBAEBAA13CE37ED","id":15893,"type":"PRG","region":"\xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6\xd1\x81\xd0\xba\xd0\xb0\xd1\x8f \xd0\x9e\xd0\xb1\xd0\xbb\xd0\xb0\xd1\x81\xd1\x82\xd1\x8c","fiasCode":"36-0-000-004-000-000-0000-0000-000","addressStr":"\xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6\xd1\x81\xd0\xba\xd0\xb0\xd1\x8f \xd0\xbe\xd0\xb1\xd0\xbb\xd0\xb0\xd1\x81\xd1\x82\xd1\x8c, \xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6-45 \xd0\xb3\xd0\xbe\xd1\x80\xd0\xbe\xd0\xb4","city":"\xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6-45 \xd0\x93\xd0\xbe\xd1\x80\xd0\xbe\xd0\xb4","countryId":"RUS","zipCode":"394045","house":"12"},{"stateFacts":["Identifiable"],"eTag":"A56F4A70CF0168ED269BC104A7781B061437E570","id":530,"type":"PLV","region":"\xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6\xd1\x81\xd0\xba\xd0\xb0\xd1\x8f \xd0\x9e\xd0\xb1\xd0\xbb\xd0\xb0\xd1\x81\xd1\x82\xd1\x8c","fiasCode":"36-0-000-004-000-000-0000-0000-000","addressStr":"\xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6\xd1\x81\xd0\xba\xd0\xb0\xd1\x8f \xd0\xbe\xd0\xb1\xd0\xbb\xd0\xb0\xd1\x81\xd1\x82\xd1\x8c, \xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6-45 \xd0\xb3\xd0\xbe\xd1\x80\xd0\xbe\xd0\xb4","city":"\xd0\x92\xd0\xbe\xd1\x80\xd0\xbe\xd0\xbd\xd0\xb5\xd0\xb6-45 \xd0\x93\xd0\xbe\xd1\x80\xd0\xbe\xd0\xb4","countryId":"RUS","zipCode":"394045","house":"12"}]}'

        httpretty.register_uri(method=httpretty.GET,
                               uri="%s/prns/1/addrs?embed=(elements)" % self.connector._rest_base_url,
                               body=addresses_body)

        result = self.connector.get_person_addresses()

        expected = {'eTag': 'EDAD381930198EC96479BAE44FA16D3FFE68BB06',
                    'elements': [
                        {
                            'addressStr': 'Воронежская область, Воронеж-45 город',
                            'city': 'Воронеж-45 Город',
                            'countryId': 'RUS',
                            'eTag': 'C3CB5C9959AFFB7F7415B9E14CBAEBAA13CE37ED',
                            'fiasCode': '36-0-000-004-000-000-0000-0000-000',
                            'house': '12',
                            'id': 15893,
                            'region': 'Воронежская Область',
                            'stateFacts': ['Identifiable'],
                            'type': 'PRG',
                            'zipCode': '394045'
                        },
                        {
                            'addressStr': 'Воронежская область, Воронеж-45 город',
                            'city': 'Воронеж-45 Город',
                            'countryId': 'RUS',
                            'eTag': 'A56F4A70CF0168ED269BC104A7781B061437E570',
                            'fiasCode': '36-0-000-004-000-000-0000-0000-000',
                            'house': '12',
                            'id': 530,
                            'region': 'Воронежская Область',
                            'stateFacts': ['Identifiable'],
                            'type': 'PLV',
                            'zipCode': '394045'
                        }
                    ],
                    'size': 2,
                    'stateFacts': ['hasSize']
                    }

        self.assertDictEqual(result, expected)

    @httpretty.activate
    def test_get_person_documents(self):
        documents_body = b'{"stateFacts":["hasSize"],"size":2,"eTag":"843F7AB702AB2D72429BB2CE4AE1CD956D7B2CB6","elements":[{"stateFacts":["Identifiable"],"eTag":"2C354B92D9F818DEA9B3702F7C2533C7779E2A40","id":3571,"type":"RF_PASSPORT","vrfStu":"VERIFIED","series":"0006","number":"000117","issueDate":"01.01.2006","issueId":"006006","issuedBy":"\xd0\xa3\xd0\xa4\xd0\x9c\xd0\xa1006"},{"stateFacts":["Identifiable"],"eTag":"D44AB2CAA9A125E8DBB6D316E307D9F0046E121D","id":21213,"type":"RF_DRIVING_LICENSE","vrfStu":"NOT_VERIFIED","series":"1231","number":"231232","issueDate":"01.08.2014","expiryDate":"01.08.2024"}]}'

        httpretty.register_uri(method=httpretty.GET,
                               uri="%s/prns/1/docs?embed=(elements)" % self.connector._rest_base_url,
                               body=documents_body)

        result = self.connector.get_person_documents()

        expected = {
            'eTag': '843F7AB702AB2D72429BB2CE4AE1CD956D7B2CB6',
            'elements': [
                {
                    'eTag': '2C354B92D9F818DEA9B3702F7C2533C7779E2A40',
                    'id': 3571,
                    'issueDate': '01.01.2006',
                    'issueId': '006006',
                    'issuedBy': 'УФМС006',
                    'number': '000117',
                    'series': '0006',
                    'stateFacts': ['Identifiable'],
                    'type': 'RF_PASSPORT',
                    'vrfStu': 'VERIFIED'
                },
                {
                    'eTag': 'D44AB2CAA9A125E8DBB6D316E307D9F0046E121D',
                    'expiryDate': '01.08.2024',
                    'id': 21213,
                    'issueDate': '01.08.2014',
                    'number': '231232',
                    'series': '1231',
                    'stateFacts': ['Identifiable'],
                    'type': 'RF_DRIVING_LICENSE',
                    'vrfStu': 'NOT_VERIFIED'
                }
            ],
            'size': 2,
            'stateFacts': ['hasSize']
        }

        self.assertDictEqual(result, expected)

    @httpretty.activate
    def test_get_person_contacts(self):
        contacts_body =  b'{"stateFacts":["hasSize"],"size":2,"eTag":"FC18786482245D5B24CB55A2EB5FC3944ADB478A","elements":[{"stateFacts":["Identifiable"],"eTag":"DEDE5C9FE49C4363ECF05B714C70D73428709846","id":14218997,"type":"CEM","vrfStu":"NOT_VERIFIED","value":"EsiaTest001@yandex.ru"},{"stateFacts":["Identifiable"],"eTag":"8C9CEDF1ADCF9770C4EB4680CE2425A803B9CC45","id":14216773,"type":"EML","vrfStu":"VERIFIED","value":"EsiaTest006@yandex.ru"}]}'

        httpretty.register_uri(method=httpretty.GET,
                               uri="%s/prns/1/ctts?embed=(elements)" % self.connector._rest_base_url,
                               body=contacts_body)

        result = self.connector.get_person_contacts()

        expected = {
            'eTag': 'FC18786482245D5B24CB55A2EB5FC3944ADB478A',
            'elements': [
                {
                    'eTag': 'DEDE5C9FE49C4363ECF05B714C70D73428709846',
                    'id': 14218997,
                    'stateFacts': ['Identifiable'],
                    'type': 'CEM',
                    'value': 'EsiaTest001@yandex.ru',
                    'vrfStu': 'NOT_VERIFIED'
                },
                {
                    'eTag': '8C9CEDF1ADCF9770C4EB4680CE2425A803B9CC45',
                     'id': 14216773,
                     'stateFacts': ['Identifiable'],
                     'type': 'EML',
                     'value': 'EsiaTest006@yandex.ru',
                     'vrfStu': 'VERIFIED'
                 }
            ],
            'size': 2,
            'stateFacts': ['hasSize']
        }

        self.assertDictEqual(result, expected)

    @httpretty.activate
    def test_incorrect_json_response(self):
        url = "%s/some_url" % self.connector._rest_base_url

        httpretty.register_uri(method=httpretty.GET,
                               uri=url,
                               body=b'{{y')

        self.assertRaises(IncorrectJsonError, self.connector.esia_request, url)

    @httpretty.activate
    def test_request_http_error(self):
        url = "%s/some_url" % self.connector._rest_base_url

        httpretty.register_uri(method=httpretty.GET,
                               uri=url,
                               status=400)

        self.assertRaises(HttpError, self.connector.esia_request, url)