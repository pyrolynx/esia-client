import base64
import datetime
import json
import urllib.parse

import OpenSSL.crypto as crypto
import aiohttp
import pytz
import requests

import esia_client.exceptions


def make_request(url: str, method: str = 'GET', params: dict = None, headers: dict = None, data: dict = None) -> dict:
    """
    Делает запрос по указанному URL с параметрами и возвращает словарь из JSON-ответа

    Raises:
        HttpError: Ошибка сети или вебсервера
        IncorrectJsonError: Ошибка парсинга JSON-ответа
    """
    try:
        response = requests.request(method, url, params=params, headers=headers, data=data)
        if response.status_code == 403:
            raise esia_client.exceptions.InaccessableInformationRequestError((params or {}).get('scope', ()))
        return response.json()
    except requests.HTTPError as e:
        raise esia_client.exceptions.HttpError(e)
    except ValueError as e:
        raise esia_client.exceptions.IncorrectJsonError(e)


async def make_async_request(
        url: str, method: str = 'GET', params: dict = None, headers: dict = None, data: dict = None) -> dict:
    """
    Делает асинхронный запрос по указанному URL с параметрами и возвращает словарь из JSON-ответа

    Raises:
        HttpError: Ошибка сети или вебсервера
        IncorrectJsonError: Ошибка парсинга JSON-ответа
    """
    try:
        async with aiohttp.client.ClientSession() as session:
            async with session.request(method, url, params=params, headers=headers, data=data) as response:
                if response.status == 403:
                    raise esia_client.exceptions.InaccessableInformationRequestError((params or {}).get('scope', ()))
                return await response.json()
    except aiohttp.client.ClientError as e:
        raise esia_client.exceptions.HttpError(e)
    except ValueError as e:
        raise esia_client.exceptions.IncorrectJsonError(e)


def sign(content: str, crt: crypto.X509, pkey: crypto.PKey) -> str:
    """
    Подписывает параметры запроса цифровой подписью

    Args:
        data: Данные, которые необходимо подписать
        crt: Путь до сертификата
        pkey: Путь до приватного ключа

    """
    bio_in = crypto._new_mem_buf(content.encode())
    PKCS7_DETACHED = 0x40
    pkcs7 = crypto._lib.PKCS7_sign(crt._x509, pkey._pkey, crypto._ffi.NULL, bio_in, PKCS7_DETACHED)
    bio_out = crypto._new_mem_buf()
    crypto._lib.i2d_PKCS7_bio(bio_out, pkcs7)
    sigbytes = crypto._bio_to_string(bio_out)
    return base64.urlsafe_b64encode(sigbytes).decode()


def get_timestamp() -> str:
    """
    Получение текущей временной метки
    """
    return datetime.datetime.now(pytz.utc).strftime('%Y.%m.%d %H:%M:%S %z').strip()


def decode_payload(base64string: str) -> dict:
    """
    Расшифровка информации из JWT токена

    Args:
        base64string: JSON в UrlencodedBaset64

    """
    offset = len(base64string) % 4
    base64string += '=' * (4 - offset) if offset else ''
    try:
        return json.loads(base64.urlsafe_b64decode(base64string))
    except (ValueError, Exception) as e:
        raise esia_client.exceptions.IncorrectMarkerError(e)


def format_uri_params(params: dict) -> str:
    """
    Форматирует строку с URI параметрами

    Args:
        params: параметры запроса

    """
    a = '&'.join((f'{key}={value}' for key, value in params.items()))

    return '&'.join((f'{key}={urllib.parse.quote(str(value).encode())}' for key, value in params.items()))
