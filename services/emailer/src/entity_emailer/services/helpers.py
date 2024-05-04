from datetime import datetime

import pytz
import requests
from flask import current_app


@staticmethod
def get_bearer_token(cls):
    """Get a valid Bearer token for the service to use."""
    token_url = current_app.config.get('ACCOUNT_SVC_AUTH_URL')
    client_id = current_app.config.get('ACCOUNT_SVC_CLIENT_ID')
    client_secret = current_app.config.get('ACCOUNT_SVC_CLIENT_SECRET')

    data = 'grant_type=client_credentials'

    # get service account token
    res = requests.post(url=token_url,
                        data=data,
                        headers={'content-type': 'application/x-www-form-urlencoded'},
                        auth=(client_id, client_secret),
                        timeout=cls.timeout)

    try:
        return res.json().get('access_token')
    except Exception:
        return None

@staticmethod
def as_legislation_timezone(date_time: datetime) -> datetime:
    """Return a datetime adjusted to the legislation timezone."""
    return date_time.astimezone(pytz.timezone(current_app.config.get('LEGISLATIVE_TIMEZONE')))


@staticmethod
def format_as_report_string(date_time: datetime) -> str:
    """Return a datetime string in this format (eg: `August 5, 2021 at 11:00 am Pacific time`)."""
    # ensure is set to correct timezone
    date_time = as_legislation_timezone(date_time)
    hour = date_time.strftime('%I').lstrip('0')
    # %p provides locale value: AM, PM (en_US); am, pm (de_DE); So forcing it to be lower in any case
    am_pm = date_time.strftime('%p').lower()
    date_time_str = date_time.strftime(f'%B %-d, %Y at {hour}:%M {am_pm} Pacific time')
    return date_time_str


@staticmethod
def query_nr_number(identifier: str):
    """Return a JSON object with name request information."""
    auth_url = current_app.config.get('NAMEX_AUTH_SVC_URL')
    username = current_app.config.get('NAMEX_SERVICE_CLIENT_USERNAME')
    secret = current_app.config.get('NAMEX_SERVICE_CLIENT_SECRET')
    namex_url = current_app.config.get('NAMEX_SVC_URL')

    # Get access token for namex-api in a different keycloak realm
    auth = requests.post(auth_url, auth=(username, secret), headers={
        'Content-Type': 'application/x-www-form-urlencoded'}, data={'grant_type': 'client_credentials'})

    # Return the auth response if an error occurs
    if auth.status_code != 200:
        return auth.json()

    token = dict(auth.json())['access_token']

    # Perform proxy call using the inputted identifier (e.g. NR 1234567)
    nr_response = requests.get(namex_url + 'requests/' + identifier, headers={
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
    })

    return nr_response