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
from sqlalchemy.types import Enum as SQLEnum
import datetime
from passlib.hash import sha512_crypt
from enum import Enum
import hashlib
import hmac
import jwt

logger = logging.getLogger(__name__)

mapper_registry = registry()
Base = mapper_registry.generate_base()


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
    election_type = Column(SQLEnum(ElectionType), server_default='STV', nullable=False)
    ballots = relationship("Ballot", back_populates='election')

    def __repr__(self):
        return f"<Election id={self.id}, owner={self.owner.__repr__()}, election_type={self.election_type}>"


class NotFoundException(Exception):
    pass


class Ballot(Base):
    __tablename__ = 'ballots'
    uuid = Column(UUIDType(), primary_key=True)
    created_at = Column(Integer(), default=lambda: round(time()))
    election_id = Column(Integer, ForeignKey('elections.id'))
    salt_uuid = Column(UUIDType(), nullable=False)
    election = relationship("Election", back_populates='ballots')
    voted = Column(Boolean, default=False)
    data = Column(JSON(none_as_null=True))

    def generate_hash(self) -> bytes:
        unhashed = self.email.encode() + self.created_at.to_bytes((self.created_at.bit_length() + 7) // 8,
                                                                  'big') + self.salt_uuid.bytes
        return hashlib.sha512(unhashed).digest()

    def generate_endpoint(self):
        hash = self.generate_hash()
        return urlsafe_b64encode(self.uuid.bytes + hash).decode('utf-8').strip('=')


class UnauthorisedException(Exception):
    pass


class AccountExistsException(Exception):
    pass


class AccountNotFoundException(Exception):
    pass


class InvalidTokenException(InvalidTokenError):
    pass


class Backend(object):
    def __init__(self, keypair, smtp_client, db_url='postgresql:///elections'):
        self._smtp_client = smtp_client
        self.priv_key = keypair[0]
        self.pub_key = keypair[1]
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
        return hmac.compare_digest(hash, ballot.generate_hash())

    def get_ballot_from_endpoint(self, endpoint):
        try:
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




