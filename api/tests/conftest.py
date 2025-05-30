import datetime
import urllib.parse
from contextlib import suppress
from unittest.mock import patch

import pytest
import responses
from flask_migrate import Migrate, upgrade
from sqlalchemy import event, text
from sqlalchemy.schema import DropConstraint, MetaData

from namex import create_app
from namex import jwt as _jwt
from namex.models import db as _db

from .python import FROZEN_DATETIME


# fixture to freeze utcnow to a fixed date-time
@pytest.fixture
def freeze_datetime_utcnow(monkeypatch):
    class _Datetime:
        @classmethod
        def utcnow(cls):
            return FROZEN_DATETIME

    monkeypatch.setattr(datetime, 'datetime', _Datetime)


@pytest.fixture(scope='session')
def app(request):
    """
    Returns session-wide application.
    """
    app = create_app('testing')

    return app


@pytest.fixture(scope='session')
def client(app):
    """
    Returns session-wide Flask test client.
    """
    return app.test_client()


@pytest.fixture(scope='session')
def jwt(app):
    """
    Returns session-wide jwt manager
    """
    return _jwt


@pytest.fixture(scope='session')
def solr(app):
    import os

    return os.getenv('SOLR_TEST_URL')


@pytest.fixture(scope='session')
def client_ctx(app):
    """
    Returns session-wide Flask test client.
    """
    with app.test_client() as c:
        yield c


@pytest.fixture(scope='session')
def db(app, request):
    """
    Returns session-wide initialised database.
    Drops all existing tables - Meta follows Postgres FKs
    """
    with app.app_context():
        # Clear out any existing tables
        metadata = MetaData()
        metadata.reflect(bind=_db.engine)
        for table in metadata.tables.values():
            for fk in table.foreign_keys:
                _db.engine.execute(DropConstraint(fk.constraint))
        with suppress(Exception):
            metadata.drop_all(bind=_db.engine)
        with suppress(Exception):
            _db.drop_all()

        sequence_sql = """SELECT sequence_name FROM information_schema.sequences
                          WHERE sequence_schema='public'
                       """

        sess = _db.session()
        for seq in [name for (name,) in sess.execute(text(sequence_sql))]:
            try:
                sess.execute(text('DROP SEQUENCE public.%s ;' % seq))
                print('DROP SEQUENCE public.%s ' % seq)
            except Exception as e:
                print('Error: {}'.format(e))
        sess.commit()

        # ############################################
        # There are 2 approaches, an empty database, or the same one that the app will use
        #     create the tables
        #     _db.create_all()
        # or
        # Use Alembic to load all of the DB revisions including supporting lookup data
        # This is the path we'll use in NAMEX!!

        # even though this isn't referenced directly, it sets up the internal configs that upgrade needs
        migrate = Migrate(app, _db)
        upgrade()

        return _db


@pytest.fixture(scope='function', autouse=True)
def session(app, db, request):
    """
    Returns function-scoped session.
    """
    with app.app_context():
        conn = db.engine.connect()
        txn = conn.begin()

        options = dict(bind=conn, binds={})
        sess = db._make_scoped_session(options=options)

        # establish  a SAVEPOINT just before beginning the test
        # (http://docs.sqlalchemy.org/en/latest/orm/session_transaction.html#using-savepoint)
        sess.begin_nested()

        @event.listens_for(sess(), 'after_transaction_end')
        def restart_savepoint(sess2, trans):
            # Detecting whether this is indeed the nested transaction of the test
            if trans.nested and not trans._parent.nested:
                # Handle where test DOESN'T session.commit(),
                sess2.expire_all()
                sess.begin_nested()

        db.session = sess

        sql = text('select 1')
        sess.execute(sql)

        yield sess

        # Cleanup
        sess.remove()
        # This instruction rollsback any commit that were executed in the tests.
        txn.rollback()
        conn.close()


@pytest.fixture(autouse=True)
def set_auth_api_url(app):
    """
    Automatically sets a dummy Auth API URL for all tests so that services relying on this config key don't fail.
    Useful when mocking endpoints that depend on this URL (e.g., affiliation checks).
    """
    app.config['AUTH_SVC_URL'] = 'https://mock-auth-api/api/v1'


@pytest.fixture
def mock_auth_affiliation():
    """
    Mocks the external Auth API affiliation endpoint so tests don't make real HTTP requests.
    Prevents failures in CI or local testing environments that don't have access to real Auth API credentials.
    """

    def _mock(nr_num='NR 123456', org_id='1234'):
        escaped_nr = urllib.parse.quote(nr_num)
        mocked_auth_url = f'https://mock-auth-api/api/v1/orgs/{org_id}/affiliations/{escaped_nr}'
        responses.add(responses.GET, mocked_auth_url, json={}, status=200)

    return _mock


@pytest.fixture(autouse=True)
def mock_gcp_queue_publish():
    """
    Mocks the Google Cloud Pub/Sub `publish` method to prevent actual message publishing during tests.
    Ensures tests run without requiring access to GCP credentials or cloud infrastructure.
    """
    with patch('namex.utils.queue_util.queue.publish') as mock_publish:
        mock_publish.return_value = None
        yield mock_publish
