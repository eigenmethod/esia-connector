import jwt
import requests.exceptions


class EsiaError(Exception):
    pass


class IncorrectJsonError(EsiaError, ValueError):
    pass


class IncorrectMarkerError(EsiaError, jwt.InvalidTokenError):
    pass


class HttpError(EsiaError, requests.exceptions.HTTPError):
    pass
