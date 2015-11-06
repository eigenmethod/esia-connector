ESIA-Connector: integration library for esia.gosuslugi.ru portal
================================================================

Abstract
--------

ESIA-Connector is an integration library for authenticating users using Russian Federation
official authentication services, provided by ESIA (aka "gosuslugi": http://esia.gosuslugi.ru),
written in python 3.


About
-----
ESIA-Connector supports authentication using OpenId Connect protocol and includes
simple built-in REST client for fetching user personal information.


Structure
---------
ESIA-Connector library contains next classes:

- ESIAAuth - class for generating url for user authentication at esia portal and handling redirected
authentication request (handler exchanges request data for ESIA access token and returns EsiaInformatioConnector instance).

- EsiaInformationConnector - class for fetching information from ESIA (at the moment only physical person endpoints have wrappers).


Installation
------------

To install ESIA-connector, simply:

.. code-block:: bash

    $ pip install esia-connector


Documentation
-------------

For more information see examples/flask_app.py - full featured integration example built on top flask
web framework. To run example flask app without library install make next steps:

1) Generate you key and certificate and place them in examples/res/ as test.key and test.crt. Create your system at ESIA and upload you certificate to ESIA server. Request ESIA for their public key - it is needed for jwt token signature verification and save it as res/esia_pub.key (or you can disable this feature). Modify examples/flask_app.py - specify your system id as esia_client_id.

2) Run in shell these commands:

.. code-block:: bash

    $ git clone git@github.com:saprun/esia-connector.git
    $ cd esia_connector
    $ pip install -r requirements-dev.txt
    $ cd esia_connector/examples
    $ python flask_app.py

Server will be listening on http://localhost:5000. Browse to that address from your web browser, click
link on the page and you'll be redirected to ESIA portal. Enter valid user credentials and you'll be
redirected back to your local server. If everything is ok, you'll see JSON containing your name.


Contribute
----------

#. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
#. Fork this repository on GitHub to start making your changes. Please note, that for development you have to install requirements manually using: pip install -r requirements-dev.txt command in cloned repository directory.

#. Write a test which shows that the bug was fixed or that the feature works as expected.
#. Send a pull request.
