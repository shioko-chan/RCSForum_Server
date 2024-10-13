from typing import Union
from fastapi import FastAPI, Response, Header
from pydantic import BaseModel
from contextlib import asynccontextmanager
from pymongo import MongoClient, ASCENDING
from bson.objectid import ObjectId

import httpx

from typing import Annotated
import asyncio
import logging
import time
import math
import uuid

import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

token_lock = asyncio.Lock()
app_access_token = None

client = MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]
poster = db["poster"]
user = db["user"]
comment = db["comment"]

user.create_index(["cid", ASCENDING])


def retry_with_limit(max_retry=5):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            for _ in range(max_retry):
                res = await func(*args, **kwargs)
                if res.status_code != 429:
                    return res
                limit, to_wait = (
                    float(res.headers["x-ogw-ratelimit-limit"]),
                    float(res.headers["x-ogw-ratelimit-reset"]),
                )
                logger.warning(
                    f"api {func.__name__} reaches the frequency limitation. Limit: {limit}, Time to recover: {to_wait}"
                )
                await asyncio.sleep(to_wait)
            return res

        return wrapper

    return decorator


async def update_app_access_token():
    global app_access_token
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                url="https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal",
                headers={"Content-Type": "application/json; charset=utf-8"},
                json={
                    "app_id": config.APP_ID,
                    "app_secret": config.APP_SECRET,
                },
            )
        data = resp.json()
        if resp.status_code == 200 and data["code"] == 0:
            time_to_live = max(float(data["expire"]) - 300.0, 300.0)
            async with token_lock:
                app_access_token = f"Bearer {data['app_access_token']}"
            logger.info(
                f"Successfully update app access token, next update is {time_to_live} seconds later."
            )
            return time_to_live
        else:
            logger.error(f"Failed update app access token: {resp.text}")
            return None

    except Exception as e:
        logger.error(f"Failed update app access token: {e}")
        return None


async def renew_app_token():
    while True:
        ttl = await update_app_access_token()
        if ttl:
            await asyncio.sleep(ttl)
        else:
            await asyncio.sleep(60.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(renew_app_token())
    yield


app = FastAPI(lifespan=lifespan)


class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None


class TempCode(BaseModel):
    code: str


@retry_with_limit(max_retry=3)
async def limited_api_req(url, headers, json, method="POST"):
    async with httpx.AsyncClient() as client:
        request = None
        match method:
            case "POST":
                request = client.post
            case "GET":
                request = client.get
        return await request(
            url=url,
            headers=headers,
            json=json,
        )


async def update_authorization(code):
    global app_access_token
    async with token_lock:
        resp = await limited_api_req(
            url="https://open.feishu.cn/open-apis/authen/v1/oidc/access_token",
            headers={
                "Authorization": app_access_token,
                "Content-Type": "application/json; charset=utf-8",
            },
            json={
                "grant_type": "authorization_code",
                "code": code,
            },
            method="POST",
        )

        body = resp.json()
        if not (resp.status_code == 200 and body["code"] == 0):
            logger.error(f"Failed to get user access token, resp: {resp.text}")
            return None, 1

        user_access_token = f"Bearer {body["data"]["access_token"]}"

        resp = await limited_api_req(
            url="https://open.feishu.cn/open-apis/authen/v1/user_info",
            headers={
                "Authorization": user_access_token,
            },
            method="GET",
        )

        body = resp.json()
        if not (resp.status_code == 200 and body["code"] == 0):
            logger.error(f"Failed to get user info, resp: {resp.text}")
            return None, 2

        data = body["data"]
        name, avatar, open_id = data["name"], data["avatar_url"], data["open_id"]

        cid = uuid.uuid4()
        id = ObjectId(open_id)
        current_user = user.find_one({"_id": id})

        if not current_user:
            user.insert_one({"_id": id, "cid": cid, "time": math.floor(time.time())})
        else:
            user.update_one(
                {"_id": id},
                {"$set": {"cid": cid, "time": math.floor(time.time())}},
            )
        return (cid, name, avatar), None


def authorization(user_token, magnitude="strong"):
    current_user = user.find_one({"cid": user_token})
    if not current_user:
        return False
    expire_duration = None
    match magnitude:
        case "strong":
            expire_duration = config.EXPIRE_DURATION
        case "weak":
            expire_duration = config.WEAK_EXPIRE_DURATION
        case _:
            raise ValueError(f"Magnitude {magnitude} is not defined")

    if time.time() - current_user.get("time") > expire_duration:
        return False
    return True


@app.post("/login")
async def login(temp_code: TempCode, response: Response):
    val, err = await update_authorization(temp_code.code)
    if err is not None:
        return {"status": err}
    cid, name, avatar = val
    response.headers["Authorization"] = cid
    return {"status": 0, "name": name, "avatar": avatar}


@app.get("/checkin")
async def checkin(authorization: Annotated[str, Header()]):
    if authorization(authorization, "weak"):
        return {"status": 1}
    return {"status": 0}


# @app.get("/")
# def read_root():
#     return {"Hello": "World"}


# @app.get("/items/{item_id}")
# def read_item(item_id: int, q: Union[str, None] = None):
#     return {"item_id": item_id, "q": q}


# @app.put("/items/{item_id}")
# def update_item(item_id: int, item: Item):
#     return {"item_name": item.price, "item_id": item_id}
