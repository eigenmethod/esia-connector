import base64
import json
import datetime
import shlex
from subprocess import Popen, PIPE
import pytz
import requests

from esia_connector.exceptions import IncorrectJsonError, HttpError


def make_request(url, method='GET', headers=None, data=None):
    """
    Makes request to given url and returns parsed response JSON
    :type url: str
    :type method: str
    :type headers: dict or None
    :type data: dict or None
    :rtype: dict
    :raises HttpError: if requests.HTTPError occurs
    :raises IncorrectJsonError: if response data cannot be parsed to JSON
    """
    try:
        response = requests.request(method, url, headers=headers, data=data)
        response.raise_for_status()
        return json.loads(response.content.decode())
    except requests.HTTPError as e:
        raise HttpError(e)
    except ValueError as e:
        raise IncorrectJsonError(e)


def sign_params(params, certificate_file, private_key_file):
    """
    Signs params adding client_secret key, containing signature based on `scope`, `timestamp`, `client_id` and `state`
    keys values.
    :param dict params: requests parameters
    :param str certificate_file: path to certificate file
    :param str private_key_file: path to private key file
    :return:signed request parameters
    :rtype: dict
    """
    plaintext = params.get('scope', '') + params.get('timestamp', '') + params.get('client_id', '') + params.get('state', '')
    cmd = 'openssl smime  -sign -md md_gost12_256 -signer {cert} -inkey {key} -outform DER'.format(
        cert=certificate_file,
        key=private_key_file
    )
    p = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE)
    raw_client_secret = p.communicate(plaintext.encode())[0]

    params.update(
        client_secret=base64.urlsafe_b64encode(raw_client_secret).decode('utf-8'),
    )
    return params


def get_timestamp():
    return datetime.datetime.now(pytz.utc).strftime('%Y.%m.%d %H:%M:%S %z').strip()

