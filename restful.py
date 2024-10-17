from typing import Annotated
from fastapi import FastAPI, Response, Header, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from contextlib import asynccontextmanager
from motor.motor_asyncio import AsyncIOMotorClient
from bson.objectid import ObjectId

import imagehash

import coloredlogs
import magic

import httpx
import aiofiles

from PIL import Image
from io import BytesIO
from datetime import datetime
from pathlib import Path
import asyncio
import logging
import time
import math
import uuid

from forms import (
    TempCodeForm,
    CreatePosterForm,
    LikeTopicForm,
    UnlikeTopicForm,
    DeleteTopicForm,
    CreateCommentForm,
    LikeCommentForm,
    UnlikeCommentForm,
    DeleteCommentForm,
)
import config

logger = logging.getLogger(__name__)
coloredlogs.install(level=logging.INFO, logger=logger)

app_access_token = None
app_access_token_lock = asyncio.Lock()

client = AsyncIOMotorClient("mongodb://localhost:27017/")
db = client["rcsforum"]
poster_collection = db["poster"]
user_collection = db["user"]
admin_collection = db["admin"]

checkin_collections = db["checkin_collections"]
checkin_collection = db["checkin_collection_0"]
checkin_collection_lock = asyncio.Lock()

Path(config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

mime = magic.Magic(mime=True)


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


async def renew_app_token(ttl):
    while True:
        if ttl:
            await asyncio.sleep(ttl)
        else:
            await asyncio.sleep(60.0)
        ttl = await update_app_access_token()


@asynccontextmanager
async def lifespan(app: FastAPI):
    index = await user_collection.create_index("cid")
    logger.info(f"create index on user collection, index name: {index}")

    if (await checkin_collections.find_one()) is None:
        await checkin_collections.insert_one({"index": 1})
    ttl = await update_app_access_token()
    asyncio.create_task(renew_app_token(ttl=ttl))
    yield


app = FastAPI(lifespan=lifespan)


@retry_with_limit(max_retry=3)
async def limited_api_req(url, headers, json=None, method="POST"):
    async with httpx.AsyncClient() as client:
        match method:
            case "POST":
                return await client.post(
                    url=url,
                    headers=headers,
                    json=json,
                )
            case "GET":
                return await client.get(
                    url=url,
                    headers=headers,
                )


async def authenticate(user_token: str, magnitude="strong"):
    user_document = await user_collection.find_one(
        {"cid": user_token}, {"_id": 1, "time": 1}
    )
    if not user_document:
        return False, f"cid {user_token} NOT FOUND"

    expire_duration = None
    match magnitude:
        case "strong":
            expire_duration = config.EXPIRE_DURATION
        case "weak":
            expire_duration = config.WEAK_EXPIRE_DURATION
        case _:
            raise ValueError(f"Magnitude {magnitude} is not defined")

    if time.time() - user_document.get("time") > expire_duration:
        return False, f"cid {user_token} EXPIRED"

    return True, user_document.get("_id")


async def update_authentication(code):
    global app_access_token
    async with app_access_token_lock:
        if app_access_token is None:
            logger.error("App access token is not acquired.")
            return None, -2
        try:
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
            user_access_token = f"Bearer {body['data']['access_token']}"
        except Exception as e:
            logger.error(f"An error occur while fetching user access token: {e}")
            return None, -1
        try:
            resp = await limited_api_req(
                url="https://open.feishu.cn/open-apis/authen/v1/user_info",
                headers={
                    "Authorization": user_access_token,
                },
                method="GET",
            )
        except Exception as e:
            logger.error(f"An error occur while fetching user info: {e}")
            return None, -1
    try:
        body = resp.json()
        if not (resp.status_code == 200 and body["code"] == 0):
            logger.error(f"Failed to get user info, resp: {resp.text}")
            return None, 2
        data = body["data"]
        name, avatar, open_id = data["name"], data["avatar_url"], data["open_id"]
    except Exception as e:
        logger.error(f"An error occur while processing user info: {e}")
        return None, -1
    try:
        user_document = await user_collection.find_one({"_id": open_id})
        if (
            user_document
            and time.time() - user_document.get("time") < config.EXPIRE_DURATION
        ):
            return (
                user_document.get("cid"),
                name,
                avatar,
                (await admin_collection.find_one({"_id": open_id}, {"_id": 1}))
                is not None,
            ), None
        cid = uuid.uuid4().hex
        info = {
            "cid": cid,
            "time": math.floor(time.time()),
            "avatar": avatar,
            "name": name,
        }
        if user_document:
            await user_collection.update_one(
                {"_id": open_id},
                {"$set": info},
            )
        else:
            info["_id"] = open_id
            await user_collection.insert_one(info)
    except Exception as e:
        logger.error(f"An error occur while upserting user info : {e}")
        return None, -1
    return (
        cid,
        name,
        avatar,
        (await admin_collection.find_one({"_id": open_id}, {"_id": 1})) is not None,
    ), None


@app.get("/user/{uid}")
async def user_info(authentication: Annotated[str, Header()], uid: str):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)

    user_document = await user_collection.find_one(
        {"_id": uid}, {"name": 1, "avatar": 1}
    )
    if not user_document:
        return JSONResponse(content={"status": 2}, status_code=404)

    is_admin = (
        await admin_collection.find_one({"_id": open_id}, {"_id": 1})
    ) is not None
    topics = []
    async for document in poster_collection.find({"uid": uid}, {"comments": 0}):
        if not is_admin and document.get("is_anonymous"):
            continue

        likes_list = document.get("likes")
        topics.append(
            {
                "pid": str(document.get("_id")),
                "title": document.get("title"),
                "content": document.get("content"),
                "time": datetime.fromtimestamp(document.get("time")).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "images": document.get("images"),
                "likes": len(likes_list),
                "liked": open_id in likes_list,
            }
        )

    return {
        "status": 0,
        "info": {
            "name": user_document.get("name"),
            "avatar": user_document.get("avatar"),
            "topics": topics,
        },
    }


@app.post("/login")
async def login(temp_code_form: TempCodeForm, response: Response):
    val, err = await update_authentication(temp_code_form.code)
    if err is not None:
        return JSONResponse(content={"status": err}, status_code=406)
    cid, name, avatar, is_admin = val
    response.headers["Authorization"] = cid
    return {"status": 0, "name": name, "avatar": avatar, "is_admin": is_admin}


@app.post("/checkin/keepalive")
async def keep_alive(authentication: Annotated[str, Header()]):
    res, open_id = await authenticate(authentication, "weak")
    if not res:
        logger.warning(f"An authentication failed, because of {open_id}")
        return JSONResponse(content={"status": 1}, status_code=401)
    async with checkin_collection_lock:
        document = await checkin_collection.find_one({"_id": open_id})
        if document:
            if (
                await checkin_collection.update_one(
                    {"_id": open_id}, {"$inc": {"time": config.KEEP_ALIVE_INTERVAL}}
                )
            ).modified_count != 1:
                return JSONResponse(content={"status": 2}, status_code=500)
        else:
            if (
                await checkin_collection.insert_one(
                    {"_id": open_id, "time": config.KEEP_ALIVE_INTERVAL}
                )
            ).inserted_id is None:
                return JSONResponse(content={"status": 3}, status_code=500)
    return {"status": 0}


@app.post("/checkin/hello")
async def hello(authentication: Annotated[str, Header()]):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    async with checkin_collection_lock:
        document = await checkin_collection.find_one({"_id": open_id})
        if not document:
            if (
                await checkin_collection.insert_one({"_id": open_id, "time": 0})
            ).inserted_id is None:
                return JSONResponse(content={"status": 2}, status_code=500)
    return {"status": 0}


@app.get("/checkin/rank")
async def rank():
    rank_list = []
    async with checkin_collection_lock:
        async for mark in checkin_collection.find({}, {"_id": 1, "time": 1}):
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


@app.get("/image/{filename}")
async def get_image(filename: str, response: Response):
    response.headers["Cache-Control"] = "public, max-age=31536000"
    path = Path(config.UPLOAD_FOLDER).joinpath(filename)
    if path.exists():
        return FileResponse(path=path)
    else:
        return Response(status_code=404)


def generate_phash(content: bytes) -> tuple[str, int]:
    try:
        stream = BytesIO(content)
        image = Image.open(stream)
        image.verify()
    except Exception as e:
        logger.error(f"An error occurred while verifying image, {e}")
        return None, 1
    try:
        stream.seek(0)
        image = Image.open(stream)
        phash_value = imagehash.phash(image)
    except Exception as e:
        logger.error(f"An error occurred while hashing image, {e}")
        return None, 2
    return str(phash_value), 0


@app.post("/image/upload")
async def upload_image(authentication: Annotated[str, Header()], image: UploadFile):
    res, _ = await authenticate(authentication, "weak")
    if not res:
        return Response(status_code=401)

    if image.size > config.MAX_IMAGE_SIZE:
        return Response(status_code=406)

    content = await image.read()
    detected_type = mime.from_buffer(content)
    if not detected_type.startswith("image/"):
        return Response(status_code=415)

    suffix = f".{detected_type.split("/")[1]}"
    if suffix not in [".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"]:
        return Response(status_code=415)

    hash_hex, errno = await asyncio.to_thread(generate_phash, content)
    match errno:
        case 1:
            return Response(status_code=415)
        case 2:
            return Response(status_code=500)

    filename = f"{hash_hex}{suffix}"
    path = Path(config.UPLOAD_FOLDER).joinpath(filename)
    if path.exists():
        return filename
    try:
        async with aiofiles.open(path, "wb") as out_image:
            await out_image.write(content)
    except Exception as e:
        logger.error(f"An error occurred while storing image, {e}")
        return Response(status_code=500)
    return filename


@app.post("/create/topic")
async def create_topic(
    authentication: Annotated[str, Header()], create_poster_form: CreatePosterForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    images_stored = create_poster_form.images
    if (
        await poster_collection.insert_one(
            {
                "uid": open_id,
                "is_anonymous": create_poster_form.is_anonymous,
                "title": create_poster_form.title,
                "likes": [],
                "content": create_poster_form.content,
                "time": time.time(),
                "images": images_stored,
                "comments": [],
            }
        )
    ).inserted_id is None:
        return JSONResponse(content={"status": 2}, status_code=500)
    return {"status": 0}


@app.post("/like/topic")
async def like_topic(
    authentication: Annotated[str, Header()], like_topic_form: LikeTopicForm
):
    res, open_id = await authenticate(authentication, "weak")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(like_topic_form.pid)}
    )
    if poster_document is None:
        return JSONResponse(content={"status": 2}, status_code=406)
    if (
        await poster_collection.update_one(
            {"_id": ObjectId(like_topic_form.pid)}, {"$addToSet": {"likes": open_id}}
        )
    ).modified_count != 1:
        return JSONResponse(content={"status": 3}, status_code=500)
    return {"status": 0}


@app.post("/unlike/topic")
async def unlike_topic(
    authentication: Annotated[str, Header()], unlike_topic_form: UnlikeTopicForm
):
    res, open_id = await authenticate(authentication, "weak")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(unlike_topic_form.pid)}
    )
    if poster_document is None:
        return JSONResponse(content={"status": 2}, status_code=406)
    if (
        await poster_collection.update_one(
            {"_id": ObjectId(unlike_topic_form.pid)}, {"$pull": {"likes": open_id}}
        )
    ).modified_count != 1:
        return JSONResponse(content={"status": 3}, status_code=500)
    return {"status": 0}


@app.post("/delete/topic")
async def delete_topic(
    authentication: Annotated[str, Header()], delete_topic_form: DeleteTopicForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)

    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(delete_topic_form.pid)}
    )
    if not poster_document:
        return JSONResponse(content={"status": 2}, status_code=406)

    if (
        poster_document.get("uid") != open_id
        and (await admin_collection.find_one({"_id": open_id}, {"_id": 1})) is None
    ):
        return JSONResponse(content={"status": 3}, status_code=403)

    if (
        await poster_collection.delete_one({"_id": poster_document.get("_id")})
    ).deleted_count != 1:
        return JSONResponse(content={"status": 4}, status_code=500)

    return {"status": 0}


@app.get("/topic")
async def get_topic(authentication: Annotated[str, Header()], page: int):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    if page < 0:
        return JSONResponse(content={"status": 2}, status_code=406)
    topics = []
    async for document in (
        poster_collection.find({}, {"comments": 0})
        .sort("time", -1)
        .skip(config.PAGE_SIZE * page)
        .limit(config.PAGE_SIZE)
    ):
        likes_list = document.get("likes")
        topic = {
            "pid": str(document.get("_id")),
            "title": document.get("title"),
            "content": document.get("content"),
            "time": datetime.fromtimestamp(document.get("time")).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "images": document.get("images"),
            "likes": len(likes_list),
            "liked": open_id in likes_list,
        }
        if document.get("is_anonymous"):
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


@app.post("/create/comment")
async def create_comment(
    authentication: Annotated[str, Header()], create_comment_form: CreateCommentForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(create_comment_form.pid)}
    )
    if not poster_document:
        return JSONResponse(content={"status": 2}, status_code=406)
    target = "comments"
    content = {
        "content": create_comment_form.content,
        "is_anonymous": create_comment_form.is_anonymous,
        "likes": [],
        "time": time.time(),
        "uid": open_id,
    }
    if create_comment_form.repeat_id is not None:
        target = f"{target}.{create_comment_form.repeat_id}.sub"
    else:
        content["images"] = create_comment_form.images
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


@app.post("/like/comment")
async def like_comment(
    authentication: Annotated[str, Header()], like_comment_form: LikeCommentForm
):
    res, open_id = await authenticate(authentication, "weak")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(like_comment_form.pid)}
    )
    if poster_document is None:
        return JSONResponse(content={"status": 2}, status_code=406)
    target = f"comments.{like_comment_form.index1}"
    if like_comment_form.index2 is not None:
        target = f"{target}.sub.{like_comment_form.index2}"
    if (
        await poster_collection.update_one(
            {"_id": ObjectId(like_comment_form.pid)},
            {"$addToSet": {f"{target}.likes": open_id}},
        )
    ).modified_count != 1:
        return JSONResponse(content={"status": 3}, status_code=500)
    return {"status": 0}


@app.post("/unlike/comment")
async def unlike_topic(
    authentication: Annotated[str, Header()], unlike_comment_form: UnlikeCommentForm
):
    res, open_id = await authenticate(authentication, "weak")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(unlike_comment_form.pid)}
    )
    if poster_document is None:
        return JSONResponse(content={"status": 2}, status_code=406)
    target = f"comments.{unlike_comment_form.index1}"
    if unlike_comment_form.index2 is not None:
        target = f"{target}.sub.{unlike_comment_form.index2}"
    if (
        await poster_collection.update_one(
            {"_id": ObjectId(unlike_comment_form.pid)},
            {"$pull": {f"{target}.likes": open_id}},
        )
    ).modified_count != 1:
        return JSONResponse(content={"status": 3}, status_code=500)
    return {"status": 0}


@app.post("/delete/comment")
async def delete_comment(
    authentication: Annotated[str, Header()], delete_comment_form: DeleteCommentForm
):
    res, open_id = await authenticate(authentication, "strong")
    if not res:
        return JSONResponse(content={"status": 1}, status_code=401)

    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(delete_comment_form.pid)}, {"comments": 1}
    )
    if not poster_document:
        return JSONResponse(content={"status": 2}, status_code=406)

    comments = poster_document.get("comments")
    if not comments:
        return JSONResponse(content={"status": 3}, status_code=406)

    if delete_comment_form.index1 >= len(comments):
        return JSONResponse(content={"status": 4}, status_code=406)

    comment = comments[delete_comment_form.index1]
    if delete_comment_form.index2 is not None:
        comments = comment.get("sub")
        if delete_comment_form.index2 >= len(comments):
            return JSONResponse(content={"status": 5}, status_code=406)
        comment = comments[delete_comment_form.index2]

    if (
        comment.get("uid") != open_id
        and (await admin_collection.find_one({"_id": open_id}, {"_id": 1})) is None
    ):
        return JSONResponse(content={"status": 3}, status_code=403)

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
        return JSONResponse(content={"status": 2}, status_code=500)

    return {"status": 0}


@app.get("/comment/{topic_id}")
async def get_comment(topic_id: str):
    poster_document = await poster_collection.find_one({"_id": ObjectId(topic_id)})
    if not poster_document:
        return JSONResponse(content={"status": 2}, status_code=404)
    return {"status": 0, "comments": poster_document.get("comments")}


@app.post("/routine")
async def routine(x_api_key: Annotated[str, Header()]):
    if x_api_key != config.X_API_KEY:
        return JSONResponse(content={"status": 1}, status_code=401)

    index = (
        await checkin_collections.find_one_and_update({}, {"$inc": {"index": 1}})
    ).get("index")
    global checkin_collection
    async with checkin_collection_lock:
        checkin_collection = db[f"checkin_collection_{index}"]

    return {"status": 0}
