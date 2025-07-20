import pymongo
import os

if os.environ.get("DB_HOST", "none") == "none":
  from dotenv import load_dotenv
  load_dotenv(dotenv_path=".env")

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = os.environ.get("DB_PORT", "27017")

client = pymongo.MongoClient("mongodb://" + DB_HOST + ":" + DB_PORT + "/")
db = client["cota"]