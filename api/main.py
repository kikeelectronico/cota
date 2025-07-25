from fastapi import FastAPI
from routers import auth

app = FastAPI()
app.include_router(auth.router)

if __name__ == "__main__":
   import uvicorn
   uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8001,
        reload=True,
    )