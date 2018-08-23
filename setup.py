from distutils.core import setup


install_requires = ['requests', 'pytz', 'cryptography']


setup(
    name='esia-client',
    version='0.1',
    description='Клиент для авторизации через ЕСИА',
    author='Kirill Churkin',
    author_email='briizzzz@mail.ru',
    url='https://github.com/pyrolynx/esia-client',
    license='BSD',
    packages=['esia_client'],
    requires=install_requires,
)
