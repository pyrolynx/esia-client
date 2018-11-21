import enum
import time
import urllib.parse
import uuid
from typing import *

from OpenSSL import crypto

import esia_client.exceptions
import esia_client.utils
import logging

__all__ = ['Settings', 'Scope', 'Auth', 'UserInfo']

logger = logging.getLogger(__name__)


class Scope(enum.Enum):
    """
    Типы запросов авторизации и информации о пользователе в ЕСИА
    """
    Authorization = 'openid'
    Fullname = 'fullname'
    Birthdate = 'birthdate'
    Sex = 'gender'
    SNILS = 'snils'
    INN = 'inn'
    Documents = 'id_doc'
    Birthplace = 'birthplace'
    Email = 'email'
    Phone = 'mobile'
    Biometry = 'bio'
    VerificationResult = 'ext_auth_result'

    def __str__(self):
        return self.value


class Settings:
    def __init__(self, esia_client_id: str, redirect_uri: str, cert_file: str, private_key_file: str,
                 esia_service_url: str, scopes: Iterable[Scope], request_timeout: float = 5):
        """
        Настройки клиента ЕСИА

        Args:
            esia_client_id: идентификатор клиента в системе ЕСИА
            redirect_uri: ссылка для переадресации пользователя после авторизации по умолчанию
            cert_file: сертификат клиента для верификации электронной подписи запросов
            private_key_file: приватный ключ для генерации электронной подписи запроса
            esia_service_url: ссылка на стенд ЕСИА
            scopes: запрашиваемые разрешения на получение данных о пользователе
            request_timeout: таймаут HTTP запросов

        """
        self.esia_client_id = esia_client_id
        self.redirect_uri = redirect_uri
        self.esia_service_url = esia_service_url
        self.scopes = tuple(scopes)
        self.timeout = request_timeout
        with open(cert_file, 'rb') as cert_file, \
                open(private_key_file, 'rb') as pkey_file:
            self._crt = crypto.load_certificate(crypto.FILETYPE_PEM, cert_file.read())
            self._pkey = crypto.load_privatekey(crypto.FILETYPE_PEM, pkey_file.read())

    @property
    def scope_string(self):
        return ' '.join((str(x) for x in self.scopes))


class UserInfo:
    """
    Клиент получения пользовательских данных из ЕСИА
    """

    def __init__(self, access_token: str, oid: str, settings: Settings):
        """
        Args:
            access_token: токен авторизации
            oid: идентификатор пользователя в системе ЕСИА
            settings: настройки клиента ЕСИА
        """
        self.token = access_token
        self.oid = oid
        self.settings = settings
        self._rest_base_url = '%s/rs' % settings.esia_service_url

    @property
    def as_dict(self):
        return {'oid': self.oid, 'token': self.token}

    def _request(self, url: str) -> dict:
        """
        Делает запрос пользовательской информации в ЕСИА

        Args:
            url: URL запроса пользовательских данных

        Raises:
            IncorrectJsonError: неверный формат ответа
            HttpError: ошибка сети или сервера

        """
        headers = {'Authorization': "Bearer %s" % self.token, 'Accept': 'application/json'}
        logger.info(f'Sending info request to; {url}')

        return esia_client.utils.make_request(url=url, headers=headers, timeout=self.settings.timeout)

    def get_person_main_info(self) -> dict:
        """
        Получение общей информации о пользователе
        """

        url = '{base}/prns/{oid}'.format(base=self._rest_base_url, oid=self.oid)
        return self._request(url=url)

    def get_person_addresses(self) -> dict:
        """
        Получение адресов регистрации пользователя
        """

        url = '{base}/prns/{oid}/addrs?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self._request(url=url)

    def get_person_contacts(self) -> dict:
        """
        Получение пользовательский контактов
        """
        url = '{base}/prns/{oid}/ctts?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self._request(url=url)

    def get_person_documents(self) -> dict:
        """
        Получение пользовательских документов
        """
        url = '{base}/prns/{oid}/docs?embed=(elements)'.format(base=self._rest_base_url, oid=self.oid)
        return self._request(url=url)

    def get_person_passport(self, doc_id: int) -> dict:
        """
        Получение документа удостоверяющего личность пользователя
        """
        url = '{base}/prns/{oid}/docs/{doc_id}'.format(base=self._rest_base_url, oid=self.oid, doc_id=doc_id)
        return self._request(url=url)


class Auth:
    """
    Клиент авторизации ЕСИА
    """
    _AUTHORIZATION_URL = '/aas/oauth2/ac'
    _TOKEN_EXCHANGE_URL = '/aas/oauth2/te'

    def __init__(self, settings: Settings):
        """
        Args:
            settings: настройки клиента ЕСИА
            request_timeout: таймаут запросов по умолчанию в секундах

        """
        self.settings = settings

    def _sign_params(self, params: dict):
        """
        Подписывает параметры цифровой подписью.
        Метод добавляет в параметры поле client_secret с закодированной в base64 цифровой подписью

        Args:
            params: параметры запроса

        """
        parts = (
            str(params.get('scope', '')),
            params.get('timestamp', ''),
            params.get('client_id', ''),
            str(params.get('state', '')),
        )

        params['client_secret'] = esia_client.utils.sign(''.join(parts), self.settings._crt, self.settings._pkey)
        logger.info(f'Sign request params. Client secret size: {len(params["client_secret"])}')

    def get_auth_url(self,
                     state: Union[str, uuid.UUID] = uuid.uuid4(),
                     redirect_uri=None, scopes: List[Scope] = None,
                     **kwargs: dict):
        """
        Генерация URL перехода на сайт ЕСИА для авторизации пользователя

        Args:
            state: идентификатор запроса
            redirect_uri: ссылка для перенаправления пользователя после авторизации
            scopes: разрешения на действия с данными учетной записи `esia_client.Scope`

        Returns:
            Ссылка авторизации
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'redirect_uri': redirect_uri or self.settings.redirect_uri,
            'scope': ' '.join([str(x) for x in scopes]) if scopes else self.settings.scope_string,
            'response_type': 'code',
            'state': state or str(uuid.uuid4()),
            'timestamp': esia_client.utils.get_timestamp(),
            'access_type': 'offline',
            **kwargs,
        }
        self._sign_params(params)

        return '{base_url}{auth_url}?{params}'.format(base_url=self.settings.esia_service_url,
                                                      auth_url=self._AUTHORIZATION_URL,
                                                      params=esia_client.utils.format_uri_params(params))

    def complete_authorization(self, code,
                               state: str = None,
                               redirect_uri: str = None,
                               scopes: List[Scope] = None) -> UserInfo:
        """
        Полученение токена авторизации и клиента запроса информации

        Args:
            code: код авторизации
            state: идентификатор сессии авторизации в формате `uuid.UUID`
            redirect_uri: URL для переадресации после авторизации
            scopes: разрешения на действия с данными учетной записи `esia_client.Scope`

        Raises:

            IncorrectJsonError: Неверный формат JSON-ответа
            HttpError: Ошибка сети или сервера
            IncorrectMarkerError: Неверный формат токена
        """

        if not state:
            state = str(uuid.uuid4())
        logger.info(f'Complete authorisation with state {state}')

        params = {
            'client_id': self.settings.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri or self.settings.redirect_uri,
            'timestamp': esia_client.utils.get_timestamp(),
            'token_type': 'Bearer',
            'scope': ' '.join([str(x) for x in scopes]) if scopes else self.settings.scope_string,
            'state': state,
        }

        self._sign_params(params)

        response_json = esia_client.utils.make_request(
            url=f"{self.settings.esia_service_url}{self._TOKEN_EXCHANGE_URL}",
            method='POST', data=params, timeout=self.settings.timeout,
        )

        access_token = response_json['access_token']
        id_token = response_json['id_token']
        payload = esia_client.utils.decode_payload(id_token.split('.')[1])
        logger.debug(f'Access token: {access_token}, id token: {id_token}')

        return UserInfo(access_token=access_token,
                        oid=self._get_user_id(payload),
                        settings=self.settings)

    @staticmethod
    def _get_user_id(payload: dict) -> str:
        """
        Получение идентификатора пользователя в системе ЕСИА из данных токена
        """
        try:
            user_id = payload['urn:esia:sbj']['urn:esia:sbj:oid']
            logger.debug(f'Found user id: {user_id}')
            return user_id
        except KeyError:
            raise esia_client.exceptions.IncorrectMarkerError(payload)


class EBS:
    _HOST_PREFIX = 'https://ebs-int.rtlabs.ru'
    _START_URL = '/api/v2/verifications'
    _RESULT_URL = '/api/v2/verifications/{sessid}/result'

    def __init__(self, oid: str, token: str, settings: Settings, host_prefix: str = None, session_id: str = None):
        self.oid = oid
        self.token = token
        self.settings = settings
        self.host = host_prefix or self._HOST_PREFIX
        self.session_id = session_id

    @property
    def as_dict(self):
        return {'oid': self.oid, 'token': self.token, 'host_prefix': self.host, 'session_id': self.session_id}

    def start_verification(self, redirect_uri: str = None) -> str:
        try:
            response = esia_client.utils.make_request(
                f'{self.host}{self._START_URL}',
                method='POST',
                headers=dict(Authorization=f'Bearer {self.token}'),
                params=dict(redirect=redirect_uri or self.settings.redirect_uri),
                json=dict(
                    metadata=dict(
                        date=str(int(time.time())),
                        user_id=str(self.oid),
                        info_system=self.settings.esia_client_id,
                        idp='ESIA',
                    )))
        except esia_client.utils.FoundLocation as e:
            logger.info(f'HTTP Found  at {e.location}')
            self.session_id = urllib.parse.urlparse(e.location).query.split('&')[0].split('=')[1]

            return e.location

        raise esia_client.exceptions.EsiaError(f'Unexpected response: {response}', )

    def get_result(self):
        response = esia_client.utils.make_request(f'{self.host}{self._RESULT_URL.format(sessid=self.session_id)}',
                                                  headers=dict(Authorization=f'Bearer {self.token}'))

        payload = esia_client.utils.decode_payload(response['extended_result'].split('.')[1])
        return payload
