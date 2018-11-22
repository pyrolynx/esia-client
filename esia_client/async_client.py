import logging
import time
import uuid
from typing import List

import furl

import esia_client
from esia_client import Scope

logger = logging.getLogger(__name__)

__all__ = ['AsyncAuth', 'AsyncUserInfo', 'AsyncEBS']


class AsyncUserInfo(esia_client.UserInfo):
    async def _request(self, url: str) -> dict:
        """
        Делает асинхронный запрос пользовательской информации в ЕСИА

        Args:
            url: URL запроса пользовательских данных

        Raises:
            IncorrectJsonError: неверный формат ответа
            HttpError: ошибка сети или сервера

        """
        headers = {'Authorization': "Bearer %s" % self.token, 'Accept': 'application/json'}
        logger.info(f'Sending info request to; {url}')

        return await esia_client.utils.make_async_request(url=url, headers=headers)

    async def get_person_main_info(self) -> dict:
        """
        Получение общей информации о пользователе
        """

        url = self._rest_base_url / 'prns' / self.oid
        return await self._request(url=url)

    async def get_person_addresses(self) -> dict:
        """
        Получение адресов регистрации пользователя
        """

        url = self._rest_base_url / 'prns' / self.oid / 'addrs'
        url.args['embed'] = '(elements)'
        return await self._request(url=url)

    async def get_person_contacts(self) -> dict:
        """
        Получение пользовательский контактов
        """
        url = self._rest_base_url / 'prns' / self.oid / 'ctts'
        url.args['embed'] = '(elements)'
        return await self._request(url=url)

    async def get_person_documents(self) -> dict:
        """
        Получение пользовательских документов
        """
        url = self._rest_base_url / 'prns' / self.oid / 'docs'
        url.args['embed'] = '(elements)'
        return await self._request(url=url)

    async def get_person_passport(self, doc_id: int) -> dict:
        """
        Получение документа удостоверяющего личность пользователя
        """
        url = self._rest_base_url / 'prns' / self.oid / 'docs' / str(doc_id)
        return await self._request(url=url)


class AsyncAuth(esia_client.Auth):

    async def complete_authorization(self, code: str,
                                     state: str = None,
                                     redirect_uri: str = None,
                                     scopes: List[Scope] = None) -> AsyncUserInfo:
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
            'redirect_uri': str(redirect_uri or self.settings.redirect_uri),
            'timestamp': esia_client.utils.get_timestamp(),
            'token_type': 'Bearer',
            'scope': ' '.join([str(x) for x in scopes]) if scopes else self.settings.scope_string,
            'state': state,
        }

        self._sign_params(params)

        response_json = await esia_client.utils.make_async_request(
            url=str(self.settings.esia_service_url / self._TOKEN_EXCHANGE_URL),
            method='POST', data=params, timeout=self.settings.timeout
        )

        access_token = response_json['access_token']
        id_token = response_json['id_token']
        payload = esia_client.utils.decode_payload(id_token.split('.')[1])
        logger.debug(f'Access token: {access_token}, id token: {id_token}')

        return AsyncUserInfo(access_token=access_token,
                             oid=self._get_user_id(payload),
                             settings=self.settings)


class AsyncEBS(esia_client.EBS):
    async def start_verification(self, redirect_uri: str = None) -> str:
        try:
            response = await esia_client.utils.make_async_request(
                str(self.service_url / self._VERIFICATION_URL),
                method='POST',
                headers=dict(Authorization=f'Bearer {self.token}'),
                params=dict(redirect=str(redirect_uri or self.settings.redirect_uri)),
                json=dict(
                    metadata=dict(
                        date=str(int(time.time())),
                        user_id=str(self.oid),
                        info_system=self.settings.esia_client_id,
                        idp='ESIA',
                    )))
        except esia_client.utils.FoundLocation as e:
            logger.info(f'HTTP Found  at {e.location}')
            self.session_id = furl.furl(e.location).args['session_id']

            return e.location

        raise esia_client.exceptions.EsiaError(f'Unexpected response: {response}', )

    async def get_result(self):
        response = await esia_client.utils.make_async_request(
            str(self.service_url / self._VERIFICATION_URL / str(self.session_id) / 'result'),
            headers=dict(Authorization=f'Bearer {self.token}')
        )
        payload = esia_client.utils.decode_payload(response['extended_result'].split('.')[1])
        logger.debug(f'Verifcation result: {payload}')
        return payload
