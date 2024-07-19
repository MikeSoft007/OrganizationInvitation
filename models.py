from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey
from database import Base
import datetime, uuid
from sqlalchemy.orm import relationship

class User(Base):
    __tablename__ = 'users'
    id                  =       Column(String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    username            =       Column(String(50), nullable=False)
    email               =       Column(String(100), unique=True, nullable=False)
    password            =       Column(String(100), nullable=False)
    organizations       =       relationship('Organization', secondary='user_organizations')


class TokenTable(Base):
    __tablename__ = "token"
    user_id         = Column(String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    access_toke     = Column(String(450), primary_key=True)
    refresh_toke    = Column(String(450), nullable=False)
    status          = Column(Boolean)
    created_date    = Column(DateTime, default=datetime.datetime.now)


class Organization(Base):
    __tablename__ = 'organizations'

    id          = Column(String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    name        = Column(String(120), nullable=False)
    description = Column(String(255), nullable=True)
    users       = relationship('User', secondary='user_organizations')


class UserOrganization(Base):
    __tablename__ = 'user_organizations'

    user_id         = Column(String(100), ForeignKey('users.id'), primary_key=True)
    organization_id = Column(String(100), ForeignKey('organizations.id'), primary_key=True)
    

class Invitation(Base):
    __tablename__      = 'invitations'
    id                 = Column(String(100), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id            = Column(String(100), ForeignKey('users.id'), nullable=False)
    organization_id    = Column(String(100), ForeignKey('organizations.id'), nullable=False)
    created_at         = Column(DateTime, default=datetime.datetime.now)
    expires_at         = Column(DateTime, nullable=False)
    is_valid           = Column(Boolean, default=True)
