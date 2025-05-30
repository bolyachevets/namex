"""Script used to regularly update INPROGRESS NRs."""
import sys
from datetime import datetime, timezone

from flask import Flask, current_app
from structured_logging import StructuredLogging
from namex.models import Event, Request, State, User, db
from namex.services import EventRecorder, queue
from sqlalchemy import text

from config import Config


def create_app(config=Config):
    """Create instance of app."""
    app = Flask(__name__)
    app.config.from_object(config)

    # Configure Structured Logging
    structured_logger = StructuredLogging()
    structured_logger.init_app(app)
    app.logger = structured_logger.get_logger()

    queue.init_app(app)
    db.init_app(app)

    return app


def get_ops_params():
    """Get params for job."""
    client_delay = int(Config.MIN_CLIENT_DELAY_SECONDS)
    examine_delay = int(Config.MIN_EXAMINE_DELAY_SECONDS)
    max_rows = int(Config.MAX_ROWS_LIMIT)
    return client_delay, examine_delay, max_rows


def inprogress_update(user: User, max_rows: int, client_delay: int, examine_delay: int) -> tuple[int, bool]:
    """Update inprogress nrs."""
    row_count = 0

    try:
        # for nrs edited by clients
        # pylint: disable=C0121
        client_edit_reqs = db.session.query(Request). \
            filter(Request.stateCd == State.INPROGRESS). \
            filter(Request.lastUpdate <= text(f"(now() at time zone 'utc') - INTERVAL \'{client_delay} SECONDS\'")). \
            filter(Request.checkedOutBy != None). \
            order_by(Request.lastUpdate.asc()). \
            limit(max_rows). \
            with_for_update().all()
        for request in client_edit_reqs:
            row_count += 1
            current_app.logger.debug(f'processing: {request.nrNum}')
            current_app.logger.debug(f'nr {request.nrNum}, state: {request.stateCd} last_update:{request.lastUpdate}')

            request.stateCd = State.DRAFT
            request.checkedOutBy = None
            request.save_to_db()
            EventRecorder.record(user, Event.SET_TO_DRAFT, request, request.json(), save_to_session=True)

        # for nrs edited by examiners
        examine_reqs = db.session.query(Request). \
            filter(Request.stateCd == State.INPROGRESS). \
            filter(Request.lastUpdate <= text(f"(now() at time zone 'utc') - INTERVAL '{examine_delay} SECONDS'")). \
            filter(Request.checkedOutBy == None). \
            order_by(Request.lastUpdate.asc()). \
            limit(max_rows). \
            with_for_update().all()

        for request in examine_reqs:
            row_count += 1
            current_app.logger.debug(f'processing: {request.nrNum}')
            current_app.logger.debug(f'nr {request.nrNum}, state: {request.stateCd} last_update:{request.lastUpdate}')

            # if this NR was previously in DRAFT, reset it to that state
            # (ie: the user walked away from an open edit window)
            event = None
            if request.previousStateCd == State.DRAFT:
                request.stateCd = State.DRAFT
                request.previousStateCd = None
                event = Event.SET_TO_DRAFT
            # otherwise put it on hold
            else:
                request.stateCd = State.HOLD
                event = Event.MARKED_ON_HOLD

            request.save_to_db()

            EventRecorder.record(user, event, request, request.json(), save_to_session=True)
        return row_count, True

    except Exception as err:  # noqa B902

        current_app.logger.error(err)
        db.session.rollback()
        return -1, False


if __name__ == '__main__':
    NRO_SERVICE_ACCOUNT = 'NRO_SERVICE_ACCOUNT'
    _app = create_app(Config)
    _app.app_context().push()
    _client_delay, _examine_delay, _max_rows = get_ops_params()

    start_time = datetime.now(timezone.utc)

    _user = User.find_by_username(current_app.config[NRO_SERVICE_ACCOUNT])
    if not _user:
        current_app.logger.error(f'Setup error: unable to load {NRO_SERVICE_ACCOUNT}.')
        sys.exit()

    _row_count, success = inprogress_update(_user, _max_rows, _client_delay, _examine_delay)
    _app.do_teardown_appcontext()
    end_time = datetime.now(timezone.utc)
    if success:
        current_app.logger.debug(f'Requests processed: {_row_count} completed in:{end_time-start_time}')
    else:
        current_app.logger.error('Failed to move timed out INPROGRESS NRs')
        sys.exit()
