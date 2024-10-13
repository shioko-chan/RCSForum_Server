from typing import Annotated, List, Optional
from fastapi import FastAPI, Response, Header, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from contextlib import asynccontextmanager
from pymongo import MongoClient, ASCENDING
from bson.objectid import ObjectId

import coloredlogs

import httpx
import aiofiles

from datetime import datetime
from pathlib import Path
import asyncio
import logging
import time
import math
import uuid

import config


logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO, logger=logger)

token_lock = asyncio.Lock()
app_access_token = None

client = MongoClient("mongodb://localhost:27017/")
db = client["rcsforum"]
poster_collection = db["poster"]
user_collection = db["user"]

checkin_collection_name = "checkin_{}"
checkin_collection_index = 0
checkin_collection = db[checkin_collection_name.format(checkin_collection_index)]

user_collection.create_index([("cid", ASCENDING)])


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
        current_user = user_collection.find_one({"_id": id})

        if not current_user:
            user_collection.insert_one(
                {
                    "_id": id,
                    "cid": cid,
                    "time": math.floor(time.time()),
                    "avatar": avatar,
                    "name": name,
                }
            )
        else:
            user_collection.update_one(
                {"_id": id},
                {
                    "$set": {
                        "cid": cid,
                        "time": math.floor(time.time()),
                        "avatar": avatar,
                        "name": name,
                    }
                },
            )
        return (cid, name, avatar), None


def authenticate(user_token, magnitude="strong"):
    user_document = user_collection.find_one({"cid": user_token})
    if not user_document:
        return False, None
    expire_duration = None
    match magnitude:
        case "strong":
            expire_duration = config.EXPIRE_DURATION
        case "weak":
            expire_duration = config.WEAK_EXPIRE_DURATION
        case _:
            raise ValueError(f"Magnitude {magnitude} is not defined")

    if time.time() - user_document.get("time") > expire_duration:
        return False, None
    return True, user_document.get("_id")


@asynccontextmanager
def lifespan(app: FastAPI):
    asyncio.create_task(renew_app_token())
    yield


app = FastAPI(lifespan=lifespan)


class TempCodeForm(BaseModel):
    code: str


@app.post("/login")
async def login(temp_code: TempCodeForm, response: Response):
    val, err = await update_authorization(temp_code.code)
    if err is not None:
        return {"status": err}
    cid, name, avatar = val
    response.headers["Authorization"] = cid
    return {"status": 0, "name": name, "avatar": avatar}


@app.get("/checkin/keepalive")
def keepalive(authentication: Annotated[str, Header()]):
    res, open_id = authenticate(authentication, "weak")
    if not res:
        return {"status": 1}

    document = checkin_collection.find_one({"_id": open_id})
    if document:
        checkin_collection.update_one(
            {"_id": open_id}, {"$inc": {"time": config.KEEP_ALIVE_INTERVAL}}
        )
    else:
        checkin_collection.insert_one(
            {"_id": open_id, "time": config.KEEP_ALIVE_INTERVAL}
        )

    return {"status": 0}


@app.get("/checkin/hello")
def hello(authentication: Annotated[str, Header()]):
    res, open_id = authenticate(authentication, "strong")
    if not res:
        return {"status": 1}

    document = checkin_collection.find_one({"_id": open_id})
    if not document:
        checkin_collection.insert_one({"_id": open_id, "time": 0})

    return {"status": 0}


class PosterForm(BaseModel):
    title: str
    content: str
    images: List[UploadFile]


@app.post("/newtopic")
async def newtopic(authentication: Annotated[str, Header()], poster: PosterForm):
    res, open_id = authenticate(authentication, "strong")
    if not res:
        return {"status": 1}

    images_stored = []
    for image in poster.images:
        if not image.content_type.startswith("image/"):
            continue
        suffix = Path(image.filename).suffix
        if suffix not in [
            ".jpg",
            ".jpeg",
            ".png",
            ".bmp",
            ".gif",
            ".tiff",
        ]:
            continue
        filename = f"{uuid.uuid4()}{suffix}"
        path = Path(config.UPLOAD_FOLDER).joinpath(filename)
        async with aiofiles.open(path, "wb") as out_image:
            await out_image.write(await image.read())
        images_stored.append(filename)

    poster_collection.insert_one(
        {
            "uid": open_id,
            "title": poster.title,
            "content": poster.content,
            "timestamp": time.time(),
            "images": images_stored,
            "comments": [],
        }
    )
    return {"status": 0}


class DelTopicForm(BaseModel):
    pid: str


@app.post("/deltopic")
def delete_topic(authentication: Annotated[str, Header()], deltopic: DelTopicForm):
    res, open_id = authenticate(authentication, "strong")
    if not res:
        return {"status": 1}
    poster_document = poster_collection.find_one({"_id": ObjectId(deltopic.pid)})
    if not poster_document:
        return {"status": 2}
    if poster_document.get("uid") != open_id:
        return {"status": 3}
    poster_collection.delete_one({"_id": poster_document.get("_id")})
    return {"status": 0}


class CommentForm(BaseModel):
    content: str
    pid: str
    repeat_id: Optional[int] = None


@app.post("/comment")
def comment(authentication: Annotated[str, Header()], comment_form: CommentForm):
    res, open_id = authenticate(authentication, "strong")
    if not res:
        return {"status": 1}
    poster_document = poster_collection.find_one({"_id": ObjectId(comment_form.pid)})
    if not poster_document:
        return {"status": 2}
    if not comment_form.repeat_id:
        poster_collection.update_one(
            {"_id": poster_document.get("_id")},
            {
                "$push": {
                    "comments": {
                        "content": comment_form.content,
                        "timestamp": time.time(),
                        "pid": open_id,
                        "sub": [],
                    }
                }
            },
        )
    else:
        poster_collection.update_one(
            {"_id": poster_document.get("_id")},
            {
                "$push": {
                    f"comments.{comment_form.repeat_id}.sub": {
                        "content": comment_form.content,
                        "timestamp": time.time(),
                        "pid": open_id,
                    }
                }
            },
        )
    return {"status": 0}


class TopicFetchForm(BaseModel):
    page: int


@app.post("/topic")
def topic(topic_fetch_form: TopicFetchForm):
    topics = []
    for document in (
        poster_collection.find({}, {"comments": 0})
        .skip(config.PAGE_SIZE * topic_fetch_form.page)
        .limit(config.PAGE_SIZE)
    ):
        user_document = user_collection.find_one(
            {"_id": document.get("uid")}, {"avatar": 1, "name": 1}
        )
        topics.append(
            {
                "title": document.get("title"),
                "content": document.get("content"),
                "timestamp": datetime.fromtimestamp(document.get("timestamp")).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "images": document.get("images"),
                "pid": str(document.get("_id")),
                "avatar": user_document.get("avatar"),
                "name": user_document.get("name"),
            }
        )

    return {"status": 0, "topics": topics}


@app.get("/image/{filename}")
def get_image(filename: str):
    return FileResponse(Path(config.UPLOAD_FOLDER).joinpath(filename))


@app.post("/routine")
async def routine(x_api_key: Annotated[str, Header()]):
    if x_api_key != config.X_API_KEY:
        return {"status": 1}
    global checkin_collection_name, checkin_collection, db, checkin_collection_index
    checkin_collection_index += 1
    checkin_collection = db[checkin_collection_name.format(checkin_collection_index)]
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
