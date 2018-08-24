from distutils.core import setup


with open('requirements.txt') as f:
    install_requires = f.readlines()


setup(
    name='esia-client',
    version='0.2',
    description='Клиент для авторизации через ЕСИА',
    author='Kirill Churkin',
    author_email='briizzzz@mail.ru',
    url='https://github.com/pyrolynx/esia-client',
    license='BSD',
    packages=['esia_client'],
    requires=install_requires,
)
