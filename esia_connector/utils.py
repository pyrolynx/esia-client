import base64
import json
import os
import datetime
import tempfile
import urllib.parse

import pytz
import requests

import esia_connector.exceptions


def make_request(url: str, method: str ='GET', params: dict = {}, headers: dict = None, data: dict = {}) -> dict:
    """
    Делает запрос по указанному URL с параметрами и возвращает словарь из JSON-ответа

    Raises:
        HttpError: Ошибка сети или вебсервера
        IncorrectJsonError: Ошибка парсинга JSON-ответа
    """
    try:
        response = requests.request(method, url, params=params, headers=headers, data=data)
        if response.status_code == 403:
            raise esia_connector.exceptions.InaccessableinformationRequestError(params.get('scope', ()))
        return response.json()
    except requests.HTTPError as e:
        raise esia_connector.exceptions.HttpError(e)
    except ValueError as e:
        raise esia_connector.exceptions.IncorrectJsonError(e)


def sign_data(data: str, cert_path: str, private_key_path: str) -> str:
    """
    Подписывает параметры запроса цифровой подписью. Закодированную подпись кладет в параметры с ключом client_secret

    Args:
        data: Данные, которые необходимо подписать
        cert_path: Путь до сертификата
        private_key_path: Путь до приватного ключа

    """
    with tempfile.NamedTemporaryFile(mode='w') as source_file,\
        tempfile.NamedTemporaryFile(mode='wb') as destination_file:
        source_file.write(data)

        cmd = 'openssl dgst  -sign -md sha256 -in {f_in} -signer {cert} -inkey {key} -out {f_out} -outform DER'
        # You can verify this signature using:
        # openssl smime -verify -inform DER -in out.msg -content msg.txt -noverify \
        # -certfile ../key/septem_sp_saprun_com.crt

        os.system(cmd.format(
            f_in=source_file.name,
            cert=cert_path,
            key=private_key_path,
            f_out=destination_file.name,
        ))

    raw_client_secret = open(destination_file.name, 'rb').read()
    if not raw_client_secret:
        raise esia_connector.exceptions.SignatureError

    return base64.urlsafe_b64encode(raw_client_secret).decode().rstrip('=')


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
        raise esia_connector.exceptions.IncorrectMarkerError(e)


def format_uri_params(params: dict) -> str:
    """
    Форматирует строку с URI параметрами

    Args:
        params: параметры запроса

    """
    a = '&'.join((f'{key}={value}' for key, value in params.items()))

    return '&'.join((f'{key}={urllib.parse.quote(str(value).encode())}' for key, value in params.items()))