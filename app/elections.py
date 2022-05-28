from base64 import urlsafe_b64encode, urlsafe_b64decode
from uuid import UUID, uuid4
from time import time
import logging
import sqlalchemy
import smtplib
from jwt import InvalidTokenError
from sqlalchemy.exc import NoResultFound, MultipleResultsFound
from sqlalchemy_utils import UUIDType
from sqlalchemy import Column, String, Integer, JSON, ForeignKey, Boolean, TIMESTAMP
from sqlalchemy.orm import Session, registry, relationship
from sqlalchemy.types import ARRAY, Enum as SQLEnum
import datetime
from passlib.hash import sha512_crypt
from enum import Enum
import hashlib
import hmac
import jwt
import os.path
from emails import GmailClient
from py3votecore.stv import STV

logger = logging.getLogger(__name__)

mapper_registry = registry()
Base = mapper_registry.generate_base()


class UnauthorisedException(Exception):
    pass


class AccountExistsException(Exception):
    pass


class AccountNotFoundException(Exception):
    pass


class InvalidTokenException(InvalidTokenError):
    pass


class NotFoundException(Exception):
    pass

class ElectionType(Enum):
    STV = 0  # For now only Single Transferable Vote is accepted


class Account(Base):
    __tablename__ = 'accounts'
    id = Column(UUIDType, primary_key=True, default=uuid4)
    username = Column(String(length=30), nullable=False, primary_key=True)
    password = Column(String(length=120), nullable=False)
    current_session_id = Column(UUIDType, nullable=True)
    last_token_reset_timestamp = Column(TIMESTAMP(), default=datetime.datetime.now)
    elections = relationship("Election", back_populates='owner')

    def __repr__(self):
        return f"<Account id={self.id}, " \
               f"username='{self.username}', " \
               f"email='{self.email}', " \
               f"current_session_id={self.current_session_id}> "


class Election(Base):
    __tablename__ = 'elections'
    id = Column(Integer(), primary_key=True)
    owner_id = Column(Integer, ForeignKey('accounts.id'))
    owner = relationship("Account", back_populates='elections')
    name = Column(String(length=30))
    election_type = Column(SQLEnum(ElectionType), server_default='STV', nullable=False)
    candidates = Column(ARRAY(String))
    available_seats = Column(Integer)
    closed = Column(Boolean, default=False)
    ballots = relationship("Ballot", back_populates='election')

    def __repr__(self):
        return f"<Election id={self.id}, name={self.name}, owner={self.owner.__repr__()}, election_type={self.election_type}>"




class Ballot(Base):
    __tablename__ = 'ballots'
    uuid = Column(UUIDType(), primary_key=True, default=uuid4)
    created_at = Column(Integer(), default=lambda: round(time()))
    election_id = Column(Integer, ForeignKey('elections.id'))
    election = relationship("Election", back_populates='ballots') 
    salt_uuid = Column(UUIDType(), nullable=False, default=uuid4)
    voted = Column(Boolean, default=False)
    data = Column(ARRAY(String))

    def __init__(self, *args, **kwargs):
        super(*args, **kwargs)
        unhashed = self.created_at.to_bytes((self.created_at.bit_length() + 7) // 8, 'big') + self.salt_uuid.bytes + self.uuid.bytes
        self.hash = hashlib.sha512(unhashed).digest()
        self.endpoint = self.generate_endpoint()
    
    def generate_endpoint(self):
        return urlsafe_b64encode(self.uuid.bytes + self.hash).decode('utf-8').strip('=')






class Backend(object):
    def __init__(self, keypair, db_url='postgresql:///elections', email_client=None, url_prefix='http://localhost'):
        self.priv_key = keypair[0]
        self.pub_key = keypair[1]
        self.email_client = GmailClient() if email_client is not None else email_client
        logger.debug('New Backend class initiated')
        logger.debug(f"Connecting to the database at: {db_url}")
        self.engine = sqlalchemy.create_engine(db_url, future=True)
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)
        
    @staticmethod
    def _hash_password(password, salt_size=16) -> String:
        return sha512_crypt.using(salt_size=salt_size).hash(password)

    @staticmethod
    def _verify_hash(password, hash):
        return sha512_crypt.verify(password, hash)

    @staticmethod
    def _split_uuid_and_hash(decoded):
        return UUID(bytes=decoded[:16], version=4), decoded[16:]

    @staticmethod
    def _verify_ballot(ballot: Ballot, hash: bytes):
        return hmac.compare_digest(hash, ballot.hash)


    def get_ballot_from_endpoint(self, endpoint):
        try:
            # potential timing attack, an attacker could in theory test for valid UUIDs
            # but this is mitigated by the fact that the uuid by itself is not enough to get the hash
            # and the chances of stumbling on a valid UUID are minimal 
            uuid, hash = self._split_uuid_and_hash(urlsafe_b64decode(endpoint + '='))
            ballot = self.session.query(Ballot).filter_by(uuid=uuid).one()
            if not self._verify_ballot(ballot, hash):
                raise NotFoundException('The hash in the endpoint does not match the ballot hash')
        except NoResultFound:
            raise NotFoundException('The ballot was not found')
        return ballot

    def add_account(self, username, password):
        if self.get_account(username) is not None:
            raise AccountExistsException()
        password_hash = self._hash_password(password)
        account = Account(username=username, password=password_hash)
        self.session.add(account)
        self.session.commit()

    def get_account(self, username) -> Account:
        return self.session.query(Account).filter_by(username=username).one_or_none()

    def get_account_by_id(self, id) -> Account:
        return self.session.query(Account).filter_by(id=id).one_or_none()

    def create_election(self, owner: Account, name: str, election_type: ElectionType, email_list):
        election = Election(owner_id=owner.id, election_type = election_type, name=name)
        self.session.add(election)
        self.session.commit()
        for email in email_list:
            ballot = Ballot(email=email, election_id=election.id)
            self.session.add(ballot)
            self.email_client.create_and_send_email(email, 'Your ballot for {election.name}!', 'Go to {self.url_prefix}/ballots/{ballot.endpoint} to vote in this election.')
        self.session.commit()

    def generate_results(election):
        if election.election_type == ElectionType.STV:
            return STV([{"count": 1, "ballot": ballot.data} for ballot in session.query(Ballots).filter_by(voted=True, election_id = election.id)]).as_dict()
        else:
            raise NotImplementedError()

    def login(self, username, password, time_till_exp=86400):
        account = self.get_account(username)
        if account is None:
            raise AccountNotFoundException()
        if not self._verify_hash(password, account.password):
            raise UnauthorisedException()
        return jwt.encode(
            {"id": str(account.id), "exp": round(time())+time_till_exp, "iat": time()},
            self.priv_key,
            algorithm="RS256",
        )

    def get_account_from_token(self, token):
        data = jwt.decode(token, self.pub_key, algorithms=["RS256"])
        acc_id = UUID(data["id"])
        acc = self.get_account_by_id(acc_id)
        if data["iat"] <= acc.last_token_reset_timestamp.timestamp():
            raise InvalidTokenError()
        return acc

    def revoke_tokens(self, account: Account):
        account.last_token_reset_timestamp = datetime.datetime.now()
        self.session.commit()



if __name__ == '__main__':

    test_priv_rsa_key = b'''-----BEGIN RSA PRIVATE KEY-----
    MIICWgIBAAKBgH0jEFHRr5bMjhOrIc15XYuZNYlpYstj2U7LICTTx6uno/z7+xdv
    dQwJkjCTkNgmxyB8u8z6vn0bGT0uFzQyjZihQFGLzcAGsBsOobqJXryHsb3hcp/W
    M1jtdW9fwGbMVUYVym0/YV83nG0F2ei4wzgn+iviXud5/WXOogDFxzQLAgMBAAEC
    gYA+YtnDALf6hVabxaifiM8zRpmjPRAM+GWhW7FVyuNz16rw+CsRXvbKnobsgtUm
    fgauUqFKKwQG2Ri3IKBe3IksgDcBiQ4d1Q4li9v1Yx3HTnuJbtu8OiA9w5/OxiTy
    I2WSCy8MSr6A1eGk/TUHjzyTtgOGlKWNL0fbuY9E2eAEGQJBAPYhH23D8Zm/ETs5
    n7oMygQfdBZL4t24aZbaUtdO46d58kEWdL4o+LttAnpIuysQyRLfgSEgZXNAdHy7
    FZNl4H8CQQCCJ8b8Z4o3+cUaY8cbC9GeorAiURg8fnov7UK03wvfpovGt2gadoty
    2YcPBrU/4GdOJohfYZxqqQSFURcsu2Z1AkAajFYUg+cie06DgeKtscV0jmP6J7NP
    0R1qjSAUY0kA/pFX3fE3tbmmlcqHoCK4MXZO19bY2OK4fMJT1eYs4PdHAkBBuN5E
    8++ahlgeFEYlBRnLVfFE0tg/K8p9SvxFIt/3Bj1Mka5StouB6g/F6ag6YhEoKFLy
    fvKh9UjgHOtr3hFFAkBY+/0mdJHVoHSNBySk9Jwd/0jprEysx1EH5ashwtm9FGT8
    C+WII54xOulymLx/S2jvSJQ2DliNWp0+rCHsqYuK
    -----END RSA PRIVATE KEY-----'''

    test_pub_rsa_key = b'''-----BEGIN PUBLIC KEY-----
    MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgH0jEFHRr5bMjhOrIc15XYuZNYlp
    Ystj2U7LICTTx6uno/z7+xdvdQwJkjCTkNgmxyB8u8z6vn0bGT0uFzQyjZihQFGL
    zcAGsBsOobqJXryHsb3hcp/WM1jtdW9fwGbMVUYVym0/YV83nG0F2ei4wzgn+ivi
    Xud5/WXOogDFxzQLAgMBAAE=
    -----END PUBLIC KEY-----'''

    backend = Backend((test_priv_rsa_key, test_pub_rsa_key), 'postgresql://tempuser:temp123@localhost/tempdb')
