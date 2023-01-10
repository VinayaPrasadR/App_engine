# -*- coding: utf-8 -*-

import os
import flask
from flask import Flask, request, redirect
import requests
import json
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery



app = flask.Flask(__name__)
app.secret_key = os.urandom(12)

credentials={
    "web": {
        "client_id": "794602203764-l4p5vpnlqrt9pmsdhocbbqfvjlgrbfmc.apps.googleusercontent.com",
        "project_id": "test-project-372908",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": "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",
        "redirect_uris": [
          "https://indus-373613.el.r.appspot.com/callback"
        ]
    }
}
json_data = json.dumps(credentials)
with open('/tmp/secret_file.json', 'w') as token:
         token.write(json_data)


SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']



@app.route('/test')
def test_api_request():
  if 'credentials' not in flask.session:
    return flask.redirect('authorize')


  credentials = google.oauth2.credentials.Credentials(
      **flask.session['credentials'])

  flask.session['credentials'] = credentials_to_dict(credentials)

  return 'success'


@app.route('/authorize')
def authorize():
 
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      client_secrets_file='/tmp/secret_file.json', scopes=SCOPES)


  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_url, state = flow.authorization_url(
   
      access_type='offline',
      include_granted_scopes='true')

  flask.session['state'] = state

  return flask.redirect(authorization_url)


@app.route('/callback')
def oauth2callback():
  
  if request.args.get('error'):
    return 'Thankyou'

  state = flask.session['state']

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      client_secrets_file='/tmp/secret_file.json', scopes=SCOPES, state=state)
  flow.redirect_uri = flask.url_for('oauth2callback', _external=True)

  authorization_response = flask.request.url
  flow.fetch_token(authorization_response=authorization_response)


  credentials = flow.credentials
  flask.session['credentials'] = credentials_to_dict(credentials)

  return flask.redirect(flask.url_for('test_api_request'))




def credentials_to_dict(credentials):
  return {'token': credentials.token,
          'refresh_token': credentials.refresh_token,
          'token_uri': credentials.token_uri,
          'client_id': credentials.client_id,
          'client_secret': credentials.client_secret,
          'scopes': credentials.scopes}

