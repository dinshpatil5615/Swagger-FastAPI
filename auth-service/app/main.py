from fastapi import FastAPI
from app.database import Base, engine
from app.routes.auth import router as auth_router

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(auth_router)


@app.get("/health")
def health():
    return {"status": "OK"}