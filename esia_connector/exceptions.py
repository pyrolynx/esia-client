import requests.exceptions


class EsiaError(Exception):
    pass


class IncorrectJsonError(EsiaError, ValueError):
    pass


class IncorrectMarkerError(EsiaError):
    pass


class HttpError(EsiaError, requests.exceptions.HTTPError):
    pass


class InaccessableinformationRequestError(EsiaError):
    pass


class SignatureError(EsiaError):
    pass

