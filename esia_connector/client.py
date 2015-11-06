import json
import uuid
from urllib.parse import urlencode

import jwt
import requests
from jwt.exceptions import ExpiredSignature, InvalidTokenError

from esia_connector.exceptions import IncorrectJsonError, HttpError, IncorrectMarkerError
from esia_connector.utils import get_timestamp, sign_params


class EsiaSettings:
    def __init__(self, esia_client_id, redirect_uri, certificate_file, private_key_file, esia_service_url, esia_scope,
                 esia_token_check_key=None):
        """
        Esia settings class
        :param str esia_client_id: client system id at ESIA
        :param str redirect_uri: uri, where browser will be redirected after authorization
        :param str certificate_file: path to client system certificate file
        :param str private_key_file: path to client system private key
        :param str esia_service_url: url of ESIA service
        :param str esia_scope: scopes keywords in single string, divided with space.
        :param str esia_token_check_key: path to ESIA key to verify access token with
        """
        self.esia_client_id = esia_client_id
        self.redirect_uri = redirect_uri
        self.certificate_file = certificate_file
        self.private_key_file = private_key_file
        self.esia_service_url = esia_service_url
        self.esia_scope = esia_scope
        self.esia_token_check_key = esia_token_check_key


class EsiaAuth:
    """
    Esia authentication connector
    """
    _ESIA_ISSUER_NAME = 'http://esia.gosuslugi.ru/'
    _AUTHORIZATION_URL = '/aas/oauth2/ac'
    _TOKEN_EXCHANGE_URL = '/aas/oauth2/te'

    def __init__(self, settings):
        """
        :param EsiaSettings settings: connector settings
        """
        self.settings = settings

    def get_auth_url(self, state=None):
        """
        Return url which end-user should visit to authorize at ESIA.
        :param str or None state: identifier, will be returned as GET parameter in redirected request after auth..
        :return: url
        :rtype: str
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'client_secret': '',
            'redirect_uri': self.settings.redirect_uri,
            'scope': self.settings.esia_scope,
            'response_type': 'code',
            'state': state or str(uuid.uuid4()),
            'timestamp': get_timestamp(),
            'access_type': 'offline'
        }

        params = sign_params(params,
                             certificate_file=self.settings.certificate_file,
                             private_key_file=self.settings.private_key_file)

        params = urlencode(sorted(params.items()))

        return '{base_url}{auth_url}?{params}'.format(base_url=self.settings.esia_service_url,
                                                      auth_url=self._AUTHORIZATION_URL,
                                                      params=params)

    def complete_authorization(self, code, state, validate_token=False):
        """
        Exchanges received code and state to access token, extracts ESIA user id from token
        and returns ESIA user id and token.
        :type code: str
        :type state: str
`       :returns: (user_id, access_token,)
        :rtype: (int, str,)
        :raises IncorrectJsonError: if response contains invalid json body
        :raises HttpError: if response status code is not 2XX
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': self.settings.redirect_uri,
            'timestamp': get_timestamp(),
            'token_type': 'Bearer',
            'scope': self.settings.esia_scope,
            'state': state,
        }

        params = sign_params(params,
                             certificate_file=self.settings.certificate_file,
                             private_key_file=self.settings.private_key_file)

        url = '{base_url}{token_url}'.format(base_url=self.settings.esia_service_url,
                                             token_url=self._TOKEN_EXCHANGE_URL)

        try:
            response = requests.post(url, data=params)
            response.raise_for_status()
            response_json = json.loads(response.content.decode())
        except requests.HTTPError as e:
            raise HttpError(e)
        except ValueError as e:
            raise IncorrectJsonError(e)

        id_token = response_json['id_token']
        parsed_token = self._parse_token(id_token)
        if validate_token:
            self._validate_token(id_token)
        # TODO: validate token
        user_id = self._get_user_id(parsed_token)
        return user_id, response_json['access_token'],

    @staticmethod
    def _parse_token(token):
        """
        :rtype: dict
        """
        return jwt.decode(token, verify=False)

    @staticmethod
    def _get_user_id(id_token):
        """
        :param dict id_token: parsed token
        """
        return id_token.get('urn:esia:sbj', {}).get('urn:esia:sbj:oid')

    def _validate_token(self, token):
        """
        :param str token: token to validate
        """
        if self.settings.esia_token_check_key is None:
            raise ValueError("To validate token you need to specify `esia_token_check_key` in settings!")

        with open(self.settings.esia_token_check_key, 'r') as f:
            data = f.read()

        try:
            jwt.decode(token,
                       key=data,
                       audience=self.settings.esia_client_id,
                       issuer=self._ESIA_ISSUER_NAME)
        except InvalidTokenError as e:
            raise IncorrectMarkerError(e)


class EsiaInformationConnectorBase:
    """
    Base class for ESIA REST based connectors
    """
    def __init__(self, access_token, oid, settings):
        """
        :param str access_token: access token
        :param int oid: ESIA object id
        :param EsiaSettings settings: connector settings
        """
        self.token = access_token
        self.oid = oid
        self.settings = settings
        self._rest_base_url = '%s/rs' % settings.esia_service_url

    def esia_request(self, endpoint_url, accept_schema=None):
        """
        Makes request to ESIA REST service and returns response JSON data.
        :param str endpoint_url: endpoint url
        :param str or None accept_schema: optional schema (version) for response data format
        :rtype: dict
        :raises IncorrectJsonError: if response contains invalid json body
        :raises HttpError: if response status code is not 2XX
        """
        headers = {
            'Authorization': "Bearer %s" % self.token
        }

        if accept_schema:
            headers['Accept'] = 'application/json; schema="%s"' % accept_schema
        else:
            headers['Accept'] = 'application/json'

        try:
            response = requests.get(endpoint_url, headers=headers)
            response.raise_for_status()
            return json.loads(response.content.decode())
        except ValueError as e:
            raise IncorrectJsonError(e)
        except requests.HTTPError as e:
            raise HttpError(e)


class EsiaPersonInformationConnector(EsiaInformationConnectorBase):
    """
    Connector for fetching physical person information from ESIA.
    """
    def get_person_main_info(self, accept_schema=None):
        url = '{base}/prns/{oid}'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_addresses(self, accept_schema=None):
        url = '{base}/prns/{oid}/addrs?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_contacts(self, accept_schema=None):
        url = '{base}/prns/{oid}/ctts?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

    def get_person_documents(self, accept_schema=None):
        url = '{base}/prns/{oid}/docs?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self.esia_request(endpoint_url=url, accept_schema=accept_schema)

