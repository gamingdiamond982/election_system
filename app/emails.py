import base64
import pickle
import os
import datetime
from collections import namedtuple
from google_auth_oauthlib.flow import Flow, InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from google.auth.transport.requests import Request
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


class BaseEmailClient(object):
    """
    A stub email client used to implement Email Clients
    """

    def send_email(self, email: MIMEMultipart):
        raise NotImplementedError()

    @staticmethod
    def create_email(recipient, subject, message) -> MIMEMultipart:
        email = MIMEMultipart()
        email['to'] = recipient
        email['subject'] = subject
        email.attach(MIMEText(message, 'plain'))
        return email
    
    def create_and_send_email(self, *args, **kwargs):
        self.send_email(self.create_email(*args, **kwargs))


class GmailClient(BaseEmailClient):
    """
    An implementation of BaseEmailClient designed to interface with the gmail apis
    """
    CLIENT_SECRET_FILE = 'client_secret.json'
    API_NAME = 'gmail'
    API_VERSION = 'v1'
    SCOPES = ['https://mail.google.com/']


    def __init__(self):
        self.service = self.create_service(self.CLIENT_SECRET_FILE, self.API_NAME, self.API_VERSION, self.SCOPES)
    
    def send_email(self, email: MIMEMultipart):
        raw_string = base64.urlsafe_b64encode(email.as_bytes()).decode()
        return self.service.users().messages().send(userId='me', body={'raw': raw_string}).execute()

    @staticmethod 
    def create_service(client_secret_file, api_name, api_version, *scopes, prefix=''):
        CLIENT_SECRET_FILE = client_secret_file
        API_SERVICE_NAME = api_name
        API_VERSION = api_version
        SCOPES = [scope for scope in scopes[0]]
        
        cred = None
        working_dir = os.getcwd()
        token_dir = 'token files'
        pickle_file = f'token_{API_SERVICE_NAME}_{API_VERSION}{prefix}.pickle'

        ### Check if token dir exists first, if not, create the folder
        if not os.path.exists(os.path.join(working_dir, token_dir)):
            os.mkdir(os.path.join(working_dir, token_dir))

        if os.path.exists(os.path.join(working_dir, token_dir, pickle_file)):
            with open(os.path.join(working_dir, token_dir, pickle_file), 'rb') as token:
                cred = pickle.load(token)

        if not cred or not cred.valid:
            if cred and cred.expired and cred.refresh_token:
                cred.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
                cred = flow.run_local_server()
            with open(os.path.join(working_dir, token_dir, pickle_file), 'wb') as token:
                pickle.dump(cred, token)

        try:
            service = build(API_SERVICE_NAME, API_VERSION, credentials=cred)
            return service
        except Exception as e:
            os.remove(os.path.join(working_dir, token_dir, pickle_file))
            return None

if __name__ == '__main__':
    GmailClient().create_and_send_email('oj.nologic@gmail.com', 'bob', 'you are gay')



