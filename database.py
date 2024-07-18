from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

#DB UR1
POSTGRES_URL= os.getenv("POSTGRES_URL")

#create a postgreSQL engine instance
engine = create_engine(POSTGRES_URL)

#create declarative base meta instance
Base = declarative_base()

#create session local class for session maker
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)