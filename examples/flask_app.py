import os

from flask import Flask, request

from esia_connector.client import EsiaSettings, EsiaAuth, EsiaPersonInformationConnector


def get_test_file(name):
    return os.path.join(os.path.dirname(__file__), 'res', name)

TEST_SETTINGS = EsiaSettings(esia_client_id='SEPCAP',
                             redirect_uri='http://localhost:5000/info',
                             certificate_file=get_test_file('test.crt'),
                             private_key_file=get_test_file('test.key'),
                             esia_service_url='https://esia-portal1.test.gosuslugi.ru',
                             esia_scope='openid http://esia.gosuslugi.ru/usr_inf')

app = Flask(__name__)


@app.route("/")
def hello():
    url = EsiaAuth(TEST_SETTINGS).get_auth_url()
    return 'Start here: <a href="%s">click</a>' % url


@app.route("/info")
def process():
    code = request.args.get('code')
    state = request.args.get('state')
    esia_auth = EsiaAuth(TEST_SETTINGS)
    oid, token, = esia_auth.complete_authorization(code, state)
    esia_connector = EsiaPersonInformationConnector(token, oid, settings=TEST_SETTINGS)
    inf = esia_connector.get_person_main_info()
    return "%s" % inf


if __name__ == "__main__":
    app.run()