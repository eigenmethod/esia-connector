import requests.exceptions


class EsiaError(Exception):
    pass


class IncorrectJsonError(EsiaError, ValueError):
    pass


class HttpError(EsiaError, requests.exceptions.HTTPError):
    pass
