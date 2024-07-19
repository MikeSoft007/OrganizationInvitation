import logging
import schemas
import jwt  # Import pyjwt as jwt
import uvicorn
from datetime import datetime, timedelta
import models
from auth_bearer import JWTBearer
from models import User, TokenTable, Invitation
from utils import get_hashed_password, verify_password, create_access_token, create_refresh_token
from database import Base, engine, SessionLocal
from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from utils import JWT_SECRET_KEY, ALGORITHM
from functools import wraps
from collections import OrderedDict
from urllib.parse import urlencode


# Set passlib logger level to ERROR
logging.getLogger('passlib').setLevel(logging.ERROR)


Base.metadata.create_all(engine)
def get_session():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


app = FastAPI(
    title="Accept invitation to join organization",
    description="An API endpoint to handle accepting invitation links to join an organization. This endpoint will validate the invitation link and automatically add the user to the specified organization upon successful validation",
    version="1.0.0",
)


@app.get("/")
async def root():
    return {"message": "Hello michael, welcome to FastAPi"}


def token_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
    
        payload = jwt.decode(kwargs['dependencies'], JWT_SECRET_KEY, ALGORITHM)
        user_id = payload['sub']
        data= kwargs['session'].query(models.TokenTable).filter_by(user_id=user_id,access_toke=kwargs['dependencies'],status=True).first()
        if data:
            return func(kwargs['dependencies'],kwargs['session'])
        
        else:
            return {'msg': "Token blocked"}
        
    return wrapper


@app.post("/api/v1/auth/register", tags=["Authentication"])
async def register_user(user: schemas.UserCreate, session: Session = Depends(get_session)):
    existing_user = session.query(models.User).filter_by(email=user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    encrypted_password = get_hashed_password(user.password)

    new_user = models.User(username=user.username, email=user.email, password=encrypted_password)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    return {"message": "user created successfully"}



@app.post('/api/v1/auth/login', response_model=schemas.TokenSchema, tags=["Authentication"])
async def login(request: schemas.requestdetails, db: Session = Depends(get_session)):
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email")
    
    if not verify_password(request.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect password"
        )
    
    access = create_access_token(user.id)
    refresh = create_refresh_token(user.id)

    token_db = models.TokenTable(user_id=user.id, access_toke=access, refresh_toke=refresh, status=True)
    db.add(token_db)
    db.commit()
    db.refresh(token_db)
    return {
        "access_token": access,
        "refresh_token": refresh,
    }

@token_required
@app.get('/api/v1/getusers', tags=["User Management"])
async def getusers(dependencies=Depends(JWTBearer()), session: Session = Depends(get_session)):
    users = session.query(models.User).all()
    return { 
        "message": "User data retrieved successfully", 
        "data": [
            { 
                "email": user.email, 
                "id": user.id, 
                "username": user.username 
            } for user in users 
        ]
    }


@app.post('/api/v1/auth/password-change', tags=["Authentication"])
def change_password(request: schemas.changepassword, db: Session = Depends(get_session)):
    print("hello")
    user = db.query(models.User).filter(models.User.email == request.email).first()
    if user is None:
        
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User not found")
    
    if not verify_password(request.old_password, user.password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid old password")
    
    encrypted_password = get_hashed_password(request.new_password)
    user.password = encrypted_password
    db.commit()
    
    return {"message": "Password changed successfully"}


@token_required
@app.post('/api/v1/auth/logout', tags=["Authentication"])
async def logout(dependencies=Depends(JWTBearer()), db: Session = Depends(get_session)):
    token=dependencies
    payload = jwt.decode(token, JWT_SECRET_KEY, ALGORITHM)
    user_id = payload['sub']
    token_record = db.query(models.TokenTable).all()
    info=[]
    for record in token_record :
        if (datetime.utcnow() - record.created_date).days >1:
            info.append(record.user_id)
    if info:
        existing_token = db.query(models.TokenTable).where(TokenTable.user_id.in_(info)).delete()
        db.commit()
        
    existing_token = db.query(models.TokenTable).filter(models.TokenTable.user_id == user_id, models.TokenTable.access_toke==token).first()
    if existing_token:
        existing_token.status=False
        db.add(existing_token)
        db.commit()
        db.refresh(existing_token)
    return {"message":"Logout Successfully"} 



# Create new organization
@app.post("/api/v1/organization", dependencies=[Depends(JWTBearer())], tags=["Organization Management"])
async def create_organizations(org: schemas.OrganizationCreate, session: Session = Depends(get_session)):
    existing_organization = session.query(models.Organization).filter_by(name=org.name).first()
    if existing_organization:
        raise HTTPException(status_code=400, detail=f"Organization name {org.name} already exists")

    new_org = models.Organization(name=org.name, description=org.description)

    session.add(new_org)
    session.commit()
    session.refresh(new_org)

    return {"message": "Organization created successfully"}


#add user to organization
@app.post("/api/v1/organizations/{org_id}/users", dependencies=[Depends(JWTBearer())], tags=["Organization Management"])
async def add_user_to_organization(org_id: str, user_data: schemas.UserAddToOrganization, session: Session = Depends(get_session)):
    print("I am here")
    if not user_data.user_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=[{"field": "user_id", "message": "user_id is required"}]
        )

    org = session.query(models.Organization).filter_by(id=org_id).first()
    if not org:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"status": "Bad request", "message": "Invalid organization ID", "statusCode": 404}
        )

    user = session.query(models.User).filter_by(id=user_data.user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"status": "Bad request", "message": "Invalid user ID", "statusCode": 404}
        )

    if user in org.users:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "Bad request", "message": "User already in organization", "statusCode": 400}
        )

    try:
        user_org = models.UserOrganization(user_id=user.id, organization_id=org.id)
        session.add(user_org)
        session.commit()

        response = OrderedDict([
            ("status", "success"),
            ("message", "User added to organization successfully")
        ])
        return response
    except Exception as e:
        session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "error", "message": "An error occurred while adding the user to the organization"}
        )


@app.post("/api/v1/invite", dependencies=[Depends(JWTBearer())], tags=["Invitation Management"])
async def generate_invite_link(invite: schemas.InvitationCreate, session: Session = Depends(get_session)):
    user = session.query(models.User).filter_by(id=invite.user_id).first()
    org = session.query(models.Organization).filter_by(id=invite.organization_id).first()

    if not user or not org:
        raise HTTPException(status_code=400, detail="Invalid user or organization ID")

    expiration = datetime.utcnow() + timedelta(days=1)
    new_invite = models.Invitation(user_id=invite.user_id, organization_id=invite.organization_id, expires_at=expiration)
    
    session.add(new_invite)
    session.commit()
    session.refresh(new_invite)

    invite_link = f"https://organization-invitation.vercel.app/api/invite/accept?{urlencode({'invitation_id': new_invite.id})}"
    
    return {"invitation_link": invite_link}



@app.post("/api/v1/invite/accept", tags=["Invitation Management"])
async def accept_invite(invite_data: schemas.InvitationAccept, session: Session = Depends(get_session)):
    invite_id = invite_data.invitation_link.split('invitation_id=')[1]
    print("Tthis is an invite link", invite_id)
    #sample : http://127.0.0.1:8000/api/invite/accept?invitation_id=4404d586-705b-4106-b0f0-72766ae85444
    invite = session.query(models.Invitation).filter_by(id=invite_id, is_valid=True).first()

    if not invite:
        raise HTTPException(status_code=400, detail="Invalid or expired invitation link")

    if invite.expires_at < datetime.utcnow():
        invite.is_valid = False
        session.commit()
        raise HTTPException(status_code=400, detail="Expired invitation link")

    user = session.query(models.User).filter_by(id=invite.user_id).first()
    org = session.query(models.Organization).filter_by(id=invite.organization_id).first()

    if not user or not org:
        raise HTTPException(status_code=400, detail="Invalid user or organization")

    user_org = models.UserOrganization(user_id=user.id, organization_id=org.id)
    session.add(user_org)
    session.commit()

    invite.is_valid = False
    session.commit()

    return {"message": "Invitation accepted, you have been added to the organization", "status": 200}



if __name__ == "__main__":
    uvicorn.run("main:app", port=7001, reload=True)
