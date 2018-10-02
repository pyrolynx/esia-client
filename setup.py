from distutils.core import setup


install_requires = ['pytz==2018.5', 'requests==2.19.1', 'pyOpenSSL==18.0.0']


setup(
    name='esia-client',
    version='0.2',
    description='Клиент для авторизации через ЕСИА',
    author='Kirill Churkin',
    author_email='briizzzz@mail.ru',
    url='https://github.com/pyrolynx/esia-client',
    license='BSD',
    packages=['esia_client'],
    install_requires=install_requires,
)
