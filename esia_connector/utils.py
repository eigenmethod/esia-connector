import base64
import os
import datetime
import tempfile

import pytz


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

    source_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    source_file.write(plaintext)
    source_file.close()
    source_path = source_file.name

    destination_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
    destination_file.close()
    destination_path = destination_file.name

    cmd = 'openssl smime -sign -md sha256 -in {f_in} -signer {cert} -inkey {key} -out {f_out} -outform DER'
    # You can verify this signature using:
    # openssl smime -verify -inform DER -in out.msg -content msg.txt -noverify \
    # -certfile ../key/septem_sp_saprun_com.crt

    os.system(cmd.format(
        f_in=source_path,
        cert=certificate_file,
        key=private_key_file,
        f_out=destination_path,
    ))

    raw_client_secret = open(destination_path, 'rb').read()

    params.update(
        client_secret=base64.urlsafe_b64encode(raw_client_secret).decode('utf-8'),
    )

    os.unlink(source_path)
    os.unlink(destination_path)

    return params


def get_timestamp():
    return datetime.datetime.now(pytz.utc).strftime('%Y.%m.%d %H:%M:%S %z').strip()