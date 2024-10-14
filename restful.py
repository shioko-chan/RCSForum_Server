from typing import Annotated, List, Optional
from fastapi import FastAPI, Response, Header, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from contextlib import asynccontextmanager
from motor.motor_asyncio import AsyncIOMotorClient
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

app_access_token = None
app_access_token_lock = asyncio.Lock()

client = AsyncIOMotorClient("mongodb://localhost:27017/")
db = client["rcsforum"]
poster_collection = db["poster"]
user_collection = db["user"]

checkin_collections = db["checkin_collections"]
checkin_collections.insert_one({"index": 0})
checkin_collection = db["checkin_collection"]
checkin_collection_lock = asyncio.Lock()


async def create_index():
    res = await user_collection.create_index("cid")
    logger.info(f"create index on user collection, index name: {res}")


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
            async with app_access_token_lock:
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
    await create_index()
    asyncio.create_task(renew_app_token())
    yield


app = FastAPI(lifespan=lifespan)


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
    async with app_access_token_lock:
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
        current_user = await user_collection.find_one({"_id": id})

        if not current_user:
            await user_collection.insert_one(
                {
                    "_id": id,
                    "cid": cid,
                    "time": math.floor(time.time()),
                    "avatar": avatar,
                    "name": name,
                }
            )
        else:
            await user_collection.update_one(
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


async def authenticate(user_token: str, magnitude="strong"):
    user_token = uuid.UUID(hex=user_token)
    user_document = await user_collection.find_one(
        {"cid": user_token}, {"_id": 1, "time": 1}
    )
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


class TempCodeForm(BaseModel):
    code: str


@app.post("/login")
async def login(temp_code_form: TempCodeForm, response: Response):
    val, err = await update_authorization(temp_code_form.code)
    if err is not None:
        return {"status": err}
    cid, name, avatar = val
    response.headers["Authorization"] = cid
    return {"status": 0, "name": name, "avatar": avatar}


@app.get("/checkin/keepalive")
async def keep_alive(authentication: Annotated[str, Header()]):
    res, open_id = await authenticate(authentication, "weak")
    if not res:
        return {"status": 1}
    async with checkin_collection_lock:
        document = await checkin_collection.find_one({"_id": open_id})
        if document:
            if (
                await checkin_collection.update_one(
                    {"_id": open_id}, {"$inc": {"time": config.KEEP_ALIVE_INTERVAL}}
                )
            ).modified_count != 1:
                return {"status": 2}
        else:
            if (
                await checkin_collection.insert_one(
                    {"_id": open_id, "time": config.KEEP_ALIVE_INTERVAL}
                )
            ).inserted_id is None:
                return {"status": 3}
    return {"status": 0}


@app.get("/checkin/hello")
async def hello(authentication: Annotated[str, Header()]):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return {"status": 1}
    async with checkin_collection_lock:
        document = await checkin_collection.find_one({"_id": open_id})
        if not document:
            if (
                await checkin_collection.insert_one({"_id": open_id, "time": 0})
            ).inserted_id is None:
                return {"status": 2}
    return {"status": 0}


@app.get("/checkin/rank")
async def rank():
    rank_list = []
    async with checkin_collection_lock:
        for mark in await checkin_collection.find():
            open_id = mark.get("_id")
            user_document = await user_collection.find_one({"_id": open_id})
            if user_document:
                rank_list.append(
                    {
                        "avatar": user_document.get("avatar"),
                        "name": user_document.get("name"),
                        "time": mark.get("time"),
                    }
                )
    return {"status": 0, "rank": rank_list}


async def store_images(image_list: List[UploadFile]):
    images_stored = []
    for image in image_list:
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
    return images_stored


@app.get("/image/{filename}")
def get_image(filename: str):
    return FileResponse(Path(config.UPLOAD_FOLDER).joinpath(filename))


class CreatePosterForm(BaseModel):
    title: str
    content: str
    is_anonymous: bool
    images: Optional[List[UploadFile]]


@app.post("/create/topic")
async def create_topic(
    authentication: Annotated[str, Header()], create_poster_form: CreatePosterForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return {"status": 1}
    if create_poster_form.images:
        images_stored = await store_images(create_poster_form.images)
    else:
        images_stored = []
    if (
        await poster_collection.insert_one(
            {
                "uid": open_id,
                "is_anon": create_poster_form.is_anonymous,
                "title": create_poster_form.title,
                "content": create_poster_form.content,
                "timestamp": time.time(),
                "images": images_stored,
                "comments": [],
            }
        )
    ).inserted_id is None:
        return {"status": 2}
    return {"status": 0}


class DeleteTopicForm(BaseModel):
    pid: str


@app.post("/delete/topic")
async def delete_topic(
    authentication: Annotated[str, Header()], delete_topic_form: DeleteTopicForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return {"status": 1}
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(delete_topic_form.pid)}
    )
    if not poster_document:
        return {"status": 2}
    if poster_document.get("uid") != open_id:
        return {"status": 3}
    if (
        await poster_collection.delete_one({"_id": poster_document.get("_id")})
    ).deleted_count != 1:
        return {"status": 4}
    return {"status": 0}


@app.get("/topic/{page}")
async def get_topic(page: int):
    topics = []
    for document in (
        await poster_collection.find({}, {"comments": 0})
        .skip(config.PAGE_SIZE * page)
        .limit(config.PAGE_SIZE)
    ):
        topic = {
            "title": document.get("title"),
            "content": document.get("content"),
            "timestamp": datetime.fromtimestamp(document.get("timestamp")).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "images": document.get("images"),
            "pid": str(document.get("_id")),
        }
        if document.get("is_anon"):
            topic["is_anonymous"] = True
        else:
            topic["is_anonymous"] = False
            user_document = await user_collection.find_one(
                {"_id": document.get("uid")}, {"avatar": 1, "name": 1}
            )
            topic["avatar"] = user_document.get("avatar")
            topic["name"] = user_document.get("name")
        topics.append(topic)
    return {"status": 0, "topics": topics}


class CreateCommentForm(BaseModel):
    content: str
    is_anonymous: bool
    pid: str
    repeat_id: Optional[int] = None
    images: Optional[List[UploadFile]] = None


@app.post("/create/comment")
async def create_comment(
    authentication: Annotated[str, Header()], create_comment_form: CreateCommentForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return {"status": 1}
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(create_comment_form.pid)}
    )
    if not poster_document:
        return {"status": 2}
    target = "comments"
    content = {
        "content": create_comment_form.content,
        "is_anon": create_comment_form.is_anonymous,
        "timestamp": time.time(),
        "uid": open_id,
    }
    if create_comment_form.repeat_id is not None:
        target = f"{target}.{create_comment_form.repeat_id}.sub"
    else:
        if create_comment_form.images:
            content["images"] = await store_images(create_comment_form.images)
        else:
            content["images"] = []
        content["sub"] = []

    if (
        not (
            await poster_collection.update_one(
                {"_id": poster_document.get("_id")},
                {"$push": {target: content}},
            )
        ).modified_count
        != 1
    ):
        {"status": 3}
    return {"status": 0}


class DeleteCommentForm(BaseModel):
    pid: str
    index1: int
    index2: Optional[int] = None


@app.post("/delete/comment")
async def delete_comment(
    authentication: Annotated[str, Header()], delete_comment_form: DeleteCommentForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return {"status": 1}
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(delete_comment_form.pid)}, {"comments": 1}
    )
    if not poster_document:
        return {"status": 2}
    comments = poster_document.get("comments")
    if not comments:
        return {"status": 3}
    if delete_comment_form.index1 >= len(comments):
        return {"status": 4}
    comment = comments[delete_comment_form.index1]
    if delete_comment_form.index2 is not None:
        comments = comment.get("sub")
        if delete_comment_form.index2 >= len(comments):
            return {"status": 5}
        comment = comments[delete_comment_form.index2]
    if comment.get("uid") != open_id:
        return {"status": 6}
    target = f"comments.{delete_comment_form.index1}"
    if delete_comment_form.index2 is not None:
        target = f"{target}.sub.{delete_comment_form.index2}"
    if (
        not (
            await poster_collection.update_one(
                {"_id": ObjectId(delete_comment_form.pid)},
                {"$unset": {target: ""}},
            )
        ).modified_count
        != 1
    ):
        return {"status": 7}
    return {"status": 0}


@app.get("/comment/{topic_id}")
async def get_comment(topic_id: str):
    poster_document = await poster_collection.find_one({"_id": ObjectId(topic_id)})
    if not poster_document:
        return {"status": 1}
    return {"status": 0, "comments": poster_document.get("comments")}


@app.post("/routine")
async def routine(x_api_key: Annotated[str, Header()]):
    if x_api_key != config.X_API_KEY:
        return {"status": 1}

    index = checkin_collections.find_one().get("index")
    checkin_collections.update_one({}, {"$inc": {"index": 1}})
    global checkin_collection
    async with checkin_collection_lock:
        checkin_collection = db[f"checkin_collection{index}"]

    return {"status": 0}
