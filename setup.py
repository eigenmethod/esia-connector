from distutils.core import setup


install_requires = ['requests', 'pytz', 'PyJWT']


classes = """
    Intended Audience :: Developers
    License :: OSI Approved :: BSD License
    Programming Language :: Python
    Programming Language :: Python :: 3
    Programming Language :: Python :: 3.4
"""
classifiers = [s.strip() for s in classes.split('\n') if s]

long_description = """
ESIA-Connector is an integration library for authenticating users using Russian Federation
official authentication services, provided by ESIA (aka "gosuslugi": http://esia.gosuslugi.ru),
written in python 3.
"""

setup(
    name='esia-connector',
    version='0.11',
    description='ESIA integration library',
    long_description=long_description,
    author='SAPRUN Team',
    author_email='andrey.beliak@saprun.com',
    url='https://github.com/saprun/esia-connector',
    license='BSD',
    classifiers=classifiers,
    packages=['esia_connector'],
    requires=install_requires,
)
