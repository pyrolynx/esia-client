from distutils.core import setup


install_requires = ['pytz==2018.5', 'pyOpenSSL==18.0.0']

setup(
    name='esia-client',
    version='0.3',
    description='Клиент для авторизации через ЕСИА',
    author='Kirill Churkin',
    author_email='briizzzz@mail.ru',
    url='https://github.com/pyrolynx/esia-client',
    license='BSD',
    packages=['esia_client'],
    install_requires=install_requires,
    extras_require={
        'sync': ['requests==2.19.1'],
        'async': ['aiohttp==3.4.4'],
    }
)
