import enum
import uuid
from typing import *

import esia_client.utils
import esia_client.exceptions

__all__ = ['Settings', 'Scope', 'Auth']


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

    def __str__(self):
        return self.value


class Settings:
    def __init__(self, esia_client_id: str, redirect_uri: str, cert_file: str, private_key_file: str,
                 esia_service_url: str, scopes: Iterable[Scope]):
        """
        Настройки клиента ЕСИА

        Args:
            esia_client_id: идентификатор клиента в системе ЕСИА
            redirect_uri: ссылка для переадресации пользователя после авторизации по умолчанию
            cert_file: сертификат клиента для верификации электронной подписи запросов
            private_key_file: приватный ключ для генерации электронной подписи запроса
            esia_service_url: ссылка на стенд ЕСИА
            scopes: запрашиваемые разрешения на получение данных о пользователе

        """
        self.esia_client_id = esia_client_id
        self.redirect_uri = redirect_uri
        self.cert_file = cert_file
        self.private_key_file = private_key_file
        self.esia_service_url = esia_service_url
        self.scopes = tuple(scopes)

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

        return esia_client.utils.make_request(url=url, headers=headers)

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
    # _ESIA_ISSUER_NAME = 'http://esia.gosuslugi.ru/'
    _AUTHORIZATION_URL = '/aas/oauth2/ac'
    _TOKEN_EXCHANGE_URL = '/aas/oauth2/te'

    def __init__(self, settings: Settings):
        """
        Args:
            settings: настройки клиента ЕСИА
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

        params['client_secret'] = esia_client.utils.sign(
            ''.join(parts), cert_path=self.settings.cert_file, private_key_path=self.settings.private_key_file
        )

    def get_auth_url(self, state: Union[str, uuid.UUID] = uuid.uuid4(), redirect_uri=None):
        """
        Генерация URL перехода на сайт ЕСИА для авторизации пользователя

        Args:
            state: идентификатор запроса
            redirect_uri: ссылка для перенаправления пользователя после авторизации

        Returns:
            Ссылка авторизации
        """
        params = {
            'client_id': self.settings.esia_client_id,
            'redirect_uri': redirect_uri or self.settings.redirect_uri,
            'scope': self.settings.scope_string,
            'response_type': 'code',
            'state': state or str(uuid.uuid4()),
            'timestamp': esia_client.utils.get_timestamp(),
            'access_type': 'offline'
        }
        self._sign_params(params)

        return '{base_url}{auth_url}?{params}'.format(base_url=self.settings.esia_service_url,
                                                      auth_url=self._AUTHORIZATION_URL,
                                                      params=esia_client.utils.format_uri_params(params))

    def complete_authorization(self, code, state: str = str(uuid.uuid4()), redirect_uri: str = None) -> UserInfo:
        """
        Полученение токена авторизации и клиента запроса информации

        Args:
            code: код авторизации
            state: идентификатор сессии авторизации в формате `uuid.UUID`
            redirect_uri: URL для переадресации после авторизации

        Raises:

            IncorrectJsonError: Неверный формат JSON-ответа
            HttpError: Ошибка сети или сервера
            IncorrectMarkerError: Неверный формат токена
        """

        params = {
            'client_id': self.settings.esia_client_id,
            'code': code,
            'grant_type': 'authorization_code',
            'redirect_uri': redirect_uri or self.settings.redirect_uri,
            'timestamp': esia_client.utils.get_timestamp(),
            'token_type': 'Bearer',
            'scope': self.settings.scope_string,
            'state': state,
        }

        self._sign_params(params)

        response_json = esia_client.utils.make_request(
            url=f"{self.settings.esia_service_url}{self._TOKEN_EXCHANGE_URL}", method='POST', data=params)

        access_token = response_json['access_token']
        id_token = response_json['id_token']
        payload = esia_client.utils.decode_payload(id_token.split('.')[1])

        return UserInfo(access_token=access_token,
                        oid=self._get_user_id(payload),
                        settings=self.settings)

    @staticmethod
    def _get_user_id(payload: dict) -> str:
        """
        Получение идентификатора пользователя в системе ЕСИА из данных токена
        """
        try:
            return payload['urn:esia:sbj']['urn:esia:sbj:oid']
        except KeyError:
            raise esia_client.exceptions.IncorrectMarkerError(payload)
