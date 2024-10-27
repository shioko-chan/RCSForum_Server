from typing import Annotated, Optional, Union
from bson import ObjectId
from fastapi import (
    FastAPI,
    Response,
    Header,
    UploadFile,
    Depends,
    HTTPException,
)
from fastapi.responses import FileResponse
from contextlib import asynccontextmanager
from motor.motor_asyncio import AsyncIOMotorClient

import imagehash

import coloredlogs
import magic

import httpx
import aiofiles

from uuid import UUID
from collections import defaultdict
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
    CreateAdminForm,
    RemoveAdminForm,
)
import config

logging.basicConfig(
    format="%(levelname)s - %(message)s - %(asctime)s", level=logging.INFO
)

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
                    "api %s reaches the frequency limitation. Limit: %s, Time to recover: %s",
                    func.__name__,
                    limit,
                    to_wait,
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
                "Successfully update app access token, next update is %s seconds later.",
                time_to_live,
            )
            return time_to_live
        else:
            logger.error("Failed update app access token: %s", resp.text)
            return None

    except Exception as e:
        logger.error("Failed update app access token: %s", e, exc_info=True)
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
    logger.info("create index on user collection, index name: %s", index)

    if (await checkin_collections.find_one()) is None:
        await checkin_collections.insert_one({"index": 1})
    ttl = await update_app_access_token()
    asyncio.create_task(renew_app_token(ttl=ttl))
    yield


async def check_if_admin(open_id: str):
    try:
        return (
            await admin_collection.find_one({"_id": open_id}, {"_id": 1})
        ) is not None
    except Exception as e:
        logger.error(
            "an error occur while check admin qualifications, %s", e, exc_info=True
        )


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


async def auth_dependency(authentication: Annotated[UUID, Header()]):
    res, open_id = await authenticate(authentication.hex, "strong")
    if not res:
        error = open_id
        logger.warn("a request failed at authentication, more info: %s", error)
        raise HTTPException(detail={"status": 1}, status_code=401)
    return open_id


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

    def _format_time(timestamp):
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

    if time.time() - user_document.get("time") > expire_duration:
        return (
            False,
            f"cid {user_token} EXPIRED, current time is {_format_time(time.time())}, expiration is {_format_time(user_document.get("time")+expire_duration)}",
        )

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
                logger.error("Failed to get user access token, resp: %s", resp.text)
                return None, 1
            user_access_token = f"Bearer {body['data']['access_token']}"
        except Exception as e:
            logger.error(
                "An error occur while fetching user access token: %s", e, exc_info=True
            )
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
            logger.error(
                f"An error occur while fetching user info: %s", e, exc_info=True
            )
            return None, -1
    try:
        body = resp.json()
        if not (resp.status_code == 200 and body["code"] == 0):
            logger.error("Failed to get user info, resp: %s", resp.text)
            return None, 2
        data = body["data"]
        name, avatar, open_id = (
            str(data["name"]),
            str(data["avatar_url"]),
            str(data["open_id"]),
        )
    except Exception as e:
        logger.error(
            "An error occurred while processing user info: %s", e, exc_info=True
        )
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
                await check_if_admin(open_id),
                open_id,
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
        logger.error("An error occur while upserting user info : %s", e, exc_info=True)
        return None, -1
    return (
        cid,
        name,
        avatar,
        await check_if_admin(open_id),
        open_id,
    ), None


@app.get("/user/{uid}")
async def user_info(open_id: Annotated[str, Depends(auth_dependency)], uid: str):
    user_document = await user_collection.find_one(
        {"_id": uid}, {"name": 1, "avatar": 1}
    )
    if not user_document:
        raise HTTPException(status_code=404)

    is_me = open_id == uid
    is_admin = await check_if_admin(open_id)
    topics = []
    async for document in poster_collection.find({"uid": uid}, {"comments": 0}).sort(
        "time", -1
    ):
        is_anon = document.get("is_anonymous")
        if not is_admin and not is_me and is_anon:
            continue

        likes_list = document.get("likes")
        topics.append(
            {
                "is_anonymous": is_anon,
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
        "name": user_document.get("name"),
        "avatar": user_document.get("avatar"),
        "topics": topics,
    }


@app.post("/login")
async def login(temp_code_form: TempCodeForm, response: Response):
    val, err = await update_authentication(temp_code_form.code)
    if err is not None:
        return HTTPException(status_code=406)
    cid, name, avatar, is_admin, open_id = val
    response.headers["authentication"] = cid
    return {
        "status": 0,
        "name": name,
        "avatar": avatar,
        "is_admin": is_admin,
        "open_id": open_id,
    }


@app.post("/checkin/keepalive")
async def keep_alive(open_id: Annotated[str, Depends(auth_dependency)]):
    async with checkin_collection_lock:
        document = await checkin_collection.find_one({"_id": open_id})
        if document:
            if (
                await checkin_collection.update_one(
                    {"_id": open_id}, {"$inc": {"time": config.KEEP_ALIVE_INTERVAL}}
                )
            ).modified_count != 1:
                raise HTTPException(status_code=500)
        else:
            if (
                await checkin_collection.insert_one(
                    {"_id": open_id, "time": config.KEEP_ALIVE_INTERVAL}
                )
            ).inserted_id is None:
                raise HTTPException(status_code=500)
    return {"status": 0}


@app.post("/checkin/hello")
async def hello(open_id: Annotated[str, Depends(auth_dependency)]):
    async with checkin_collection_lock:
        document = await checkin_collection.find_one({"_id": open_id})
        if not document:
            if (
                await checkin_collection.insert_one({"_id": open_id, "time": 0})
            ).inserted_id is None:
                raise HTTPException(status_code=500)
    return {"status": 0}


@app.get("/checkin/ranks")
async def rank():
    rank_list = []
    async with checkin_collection_lock:
        async for mark in checkin_collection.find({}, {"_id": 1, "time": 1}).sort(
            "time", -1
        ):
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


@app.get("/checkin/ranksacc")
async def rankacc():
    try:
        cnt = (await checkin_collections.find_one()).get("index")
    except Exception as e:
        logger.error("in rank acc, an error occur: %s", e, exc_info=True)
        raise HTTPException(status_code=500)
    res = defaultdict(float)
    for i in range(cnt):
        async for mark in db[f"checkin_collection_{i}"].find({}, {"_id": 1, "time": 1}):
            res[mark.get("_id")] += mark.get("time")

    rank_list = []
    for open_id, time in await asyncio.to_thread(
        sorted, res.items(), key=lambda item: item[1], reverse=True
    ):
        user_document = await user_collection.find_one({"_id": open_id})
        if user_document:
            rank_list.append(
                {
                    "avatar": user_document.get("avatar"),
                    "name": user_document.get("name"),
                    "time": time,
                }
            )
    return {
        "status": 0,
        "rank": rank_list,
    }


@app.get("/image/{filename}")
async def get_image(filename: str, response: Response):
    if not filename.endswith((".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp")):
        raise HTTPException(status_code=400)

    upload_folder = Path(config.UPLOAD_FOLDER)
    path = (upload_folder / filename).resolve()

    if path.is_file() and str(path).startswith(str(upload_folder.resolve())):
        response.headers["Cache-Control"] = "public, max-age=31536000"
        return FileResponse(path=path)
    else:
        raise HTTPException(status_code=404)


def generate_phash(content: bytes) -> tuple[Optional[str], Union[int, BytesIO]]:
    try:
        stream = BytesIO(content)
        image = Image.open(stream)
        image.verify()
    except Exception as e:
        logger.error("An error occurred while verifying image, %s", e, exc_info=True)
        return None, 1
    try:
        stream.seek(0)
        image = Image.open(stream)
        phash_value = imagehash.phash(image)
    except Exception as e:
        logger.error("An error occurred while hashing image, %s", e, exc_info=True)
        return None, 2
    stream.seek(0)
    return str(phash_value), stream


def compress(
    stream: BytesIO, ext: str, resize_ratio=0.75, quality=75
) -> Optional[BytesIO]:
    try:
        img = Image.open(stream)
        width, height = img.size
        img = img.resize(
            (int(width * resize_ratio), int(height * resize_ratio)), Image.LANCZOS
        )
        new_stream = BytesIO()
        img.save(new_stream, format=ext, quality=quality, optimize=True)
        new_stream.seek(0)
        return new_stream
    except Exception as e:
        logger.error("An error occurred while compressing image, %s", e, exc_info=True)
        return None


@app.post("/image/upload")
async def upload_image(
    open_id: Annotated[str, Depends(auth_dependency)], image: UploadFile
):
    if image.size > config.MAX_IMAGE_SIZE:
        raise HTTPException(status_code=406)

    content = await image.read()
    detected_type = magic.Magic(mime=True).from_buffer(content)
    if not detected_type.startswith("image/"):
        raise HTTPException(status_code=415)

    suffix = f".{detected_type.split("/")[1]}"
    if suffix not in (".jpg", ".jpeg", ".png", ".bmp", ".gif", ".webp"):
        raise HTTPException(status_code=415)

    hash_hex, result = await asyncio.to_thread(generate_phash, content)
    if hash_hex is None:
        match result:
            case 1:
                raise HTTPException(status_code=415)
            case 2:
                raise HTTPException(status_code=500)
    content_stream = result

    filename = f"{hash_hex}{suffix}"
    path = Path(config.UPLOAD_FOLDER) / filename
    if path.exists():
        return filename

    extension_to_format = {
        ".jpg": "JPEG",
        ".jpeg": "JPEG",
        ".png": "PNG",
        ".gif": "GIF",
        ".bmp": "BMP",
        ".webp": "WEBP",
    }

    content_stream = await asyncio.to_thread(
        compress, content_stream, extension_to_format[suffix]
    )
    if content_stream is None:
        raise HTTPException(status_code=500)
    try:
        async with aiofiles.open(path, "wb") as out_image:
            await out_image.write(content_stream.getbuffer())
    except Exception as e:
        logger.error("An error occurred while storing image, %s", e, exc_info=True)
        raise HTTPException(status_code=500)
    return filename


@app.post("/create/topic")
async def create_topic(
    open_id: Annotated[str, Depends(auth_dependency)],
    create_poster_form: CreatePosterForm,
):
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
        raise HTTPException(status_code=500)
    return {"status": 0}


@app.post("/like/topic")
async def like_topic(
    open_id: Annotated[str, Depends(auth_dependency)], like_topic_form: LikeTopicForm
):
    poster_document = await poster_collection.find_one({"_id": like_topic_form.pid})
    if poster_document is None:
        raise HTTPException(status_code=406)
    if (
        await poster_collection.update_one(
            {"_id": like_topic_form.pid}, {"$addToSet": {"likes": open_id}}
        )
    ).modified_count != 1:
        raise HTTPException(status_code=500)
    return {"status": 0}


@app.post("/unlike/topic")
async def unlike_topic(
    open_id: Annotated[str, Depends(auth_dependency)],
    unlike_topic_form: UnlikeTopicForm,
):
    poster_document = await poster_collection.find_one({"_id": unlike_topic_form.pid})
    if poster_document is None:
        raise HTTPException(status_code=406)
    if (
        await poster_collection.update_one(
            {"_id": unlike_topic_form.pid}, {"$pull": {"likes": open_id}}
        )
    ).modified_count != 1:
        raise HTTPException(status_code=500)
    return {"status": 0}


@app.post("/delete/topic")
async def delete_topic(
    open_id: Annotated[str, Depends(auth_dependency)],
    delete_topic_form: DeleteTopicForm,
):
    poster_document = await poster_collection.find_one({"_id": delete_topic_form.pid})
    if not poster_document:
        raise HTTPException(status_code=406)

    if poster_document.get("uid") != open_id and not await check_if_admin(open_id):
        raise HTTPException(status_code=403)

    if (
        await poster_collection.delete_one({"_id": poster_document.get("_id")})
    ).deleted_count != 1:
        raise HTTPException(status_code=500)

    return {"status": 0}


@app.get("/topic")
async def get_topic(open_id: Annotated[str, Depends(auth_dependency)], page: int):
    if page < 0:
        raise HTTPException(status_code=406)
    topics = []

    is_admin = await check_if_admin(open_id)
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
            if is_admin:
                topic["uid"] = document.get("uid")
        else:
            topic["is_anonymous"] = False
            topic["uid"] = document.get("uid")
            user_document = await user_collection.find_one(
                {"_id": document.get("uid")}, {"avatar": 1, "name": 1}
            )
            topic["avatar"] = user_document.get("avatar")
            topic["name"] = user_document.get("name")

        topics.append(topic)

    return {"status": 0, "topics": topics}


@app.post("/create/comment")
async def create_comment(
    open_id: Annotated[str, Depends(auth_dependency)],
    create_comment_form: CreateCommentForm,
):
    poster_document = await poster_collection.find_one({"_id": create_comment_form.pid})
    if not poster_document:
        raise HTTPException(status_code=406)
    target = "comments"
    content = {
        "content": create_comment_form.content,
        "is_anonymous": create_comment_form.is_anonymous,
        "likes": [],
        "time": time.time(),
        "uid": open_id,
    }
    if create_comment_form.index_1 is not None:
        target = f"{target}.{create_comment_form.index_1}.sub"
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
    open_id: Annotated[str, Depends(auth_dependency)],
    like_comment_form: LikeCommentForm,
):
    poster_document = await poster_collection.find_one({"_id": like_comment_form.pid})
    if poster_document is None:
        raise HTTPException(status_code=406)
    target = f"comments.{like_comment_form.index_1}"
    if like_comment_form.index_2 is not None:
        target = f"{target}.sub.{like_comment_form.index_2}"
    if (
        await poster_collection.update_one(
            {"_id": like_comment_form.pid},
            {"$addToSet": {f"{target}.likes": open_id}},
        )
    ).modified_count != 1:
        raise HTTPException(status_code=500)
    return {"status": 0}


@app.post("/unlike/comment")
async def unlike_topic(
    open_id: Annotated[str, Depends(auth_dependency)],
    unlike_comment_form: UnlikeCommentForm,
):

    poster_document = await poster_collection.find_one({"_id": unlike_comment_form.pid})
    if poster_document is None:
        raise HTTPException(status_code=406)
    target = f"comments.{unlike_comment_form.index_1}"
    if unlike_comment_form.index_2 is not None:
        target = f"{target}.sub.{unlike_comment_form.index_2}"
    if (
        await poster_collection.update_one(
            {"_id": unlike_comment_form.pid},
            {"$pull": {f"{target}.likes": open_id}},
        )
    ).modified_count != 1:
        raise HTTPException(status_code=500)
    return {"status": 0}


@app.post("/delete/comment")
async def delete_comment(
    open_id: Annotated[str, Depends(auth_dependency)],
    delete_comment_form: DeleteCommentForm,
):
    poster_document = await poster_collection.find_one(
        {"_id": delete_comment_form.pid}, {"comments": 1}
    )
    if not poster_document:
        raise HTTPException(status_code=406)

    comments = poster_document.get("comments")
    if not comments:
        raise HTTPException(status_code=406)

    if delete_comment_form.index_1 >= len(comments):
        raise HTTPException(status_code=406)

    comment = comments[delete_comment_form.index_1]
    if delete_comment_form.index_2 is not None:
        comments = comment.get("sub")
        if delete_comment_form.index_2 >= len(comments):
            raise HTTPException(status_code=406)
        comment = comments[delete_comment_form.index_2]

    if comment.get("uid") != open_id and not await check_if_admin(open_id):
        raise HTTPException(status_code=403)

    fields = ["content", "is_anonymous", "likes", "time", "uid"]
    target = f"comments.{delete_comment_form.index_1}"

    if delete_comment_form.index_2 is None:
        fields.append("images")
    else:
        target = f"{target}.sub.{delete_comment_form.index_2}"

    targets = {f"{target}.{field}": "" for field in fields}

    res = await poster_collection.update_one(
        {"_id": delete_comment_form.pid},
        {"$unset": targets, "$set": {f"{target}.is_deleted": True}},
    )
    if res.modified_count != 1:
        print(res.__str__(), res.modified_count)
        raise HTTPException(status_code=500)

    return {"status": 0}


@app.get("/comment/{pid}")
async def get_comment(open_id: Annotated[str, Depends(auth_dependency)], pid: str):
    poster_document = await poster_collection.find_one(
        {"_id": ObjectId(pid)}, {"comments": 1}
    )
    if not poster_document:
        raise HTTPException(status_code=404)

    documents = poster_document.get("comments")
    comments = []
    is_admin = await check_if_admin(open_id)
    for document in documents:
        if not document.get("is_deleted"):
            likes_list = document.get("likes")
            comment = {
                "content": document.get("content"),
                "time": datetime.fromtimestamp(document.get("time")).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "images": document.get("images"),
                "subs": [],
                "likes": len(likes_list),
                "liked": open_id in likes_list,
            }
            if document.get("is_anonymous"):
                comment["is_anonymous"] = True
                if is_admin:
                    comment["uid"] = document.get("uid")
            else:
                comment["is_anonymous"] = False
                uid = document.get("uid")
                comment["uid"] = uid
                user_document = await user_collection.find_one(
                    {"_id": uid}, {"avatar": 1, "name": 1}
                )
                comment["avatar"] = user_document.get("avatar")
                comment["name"] = user_document.get("name")

        for document in document.get("sub"):
            if document.get("is_deleted"):
                comment["subs"].append({})
                continue

            likes_list = document.get("likes")
            sub_comment = {
                "content": document.get("content"),
                "time": datetime.fromtimestamp(document.get("time")).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "likes": len(likes_list),
                "liked": open_id in likes_list,
            }
            if document.get("is_anonymous"):
                sub_comment["is_anonymous"] = True
                if is_admin:
                    sub_comment["uid"] = document.get("uid")
            else:
                sub_comment["is_anonymous"] = False
                uid = document.get("uid")
                sub_comment["uid"] = uid
                user_document = await user_collection.find_one(
                    {"_id": uid}, {"avatar": 1, "name": 1}
                )
                sub_comment["avatar"] = user_document.get("avatar")
                sub_comment["name"] = user_document.get("name")
            comment["subs"].append(sub_comment)

        comments.append(comment)

    return {"status": 0, "comments": comments}


async def x_api_key_dependency(x_api_key: Annotated[str, Header()]):
    if x_api_key != config.X_API_KEY:
        raise HTTPException(status_code=401)
    return True


@app.post("/routine")
async def routine(_: Annotated[bool, Depends(x_api_key_dependency)]):
    index = (
        await checkin_collections.find_one_and_update({}, {"$inc": {"index": 1}})
    ).get("index")
    global checkin_collection
    async with checkin_collection_lock:
        checkin_collection = db[f"checkin_collection_{index}"]

    return {"status": 0}


@app.post("/setadmin")
async def set_admin(
    _: Annotated[bool, Depends(x_api_key_dependency)],
    create_admin_form: CreateAdminForm,
):
    if (await admin_collection.find_one({"_id": create_admin_form.open_id})) is None:
        if (
            await admin_collection.insert_one({"_id": create_admin_form.open_id})
        ).inserted_id is None:
            raise HTTPException(status_code=500)

    await user_collection.delete_one({"_id": create_admin_form.open_id})

    return {"status": 0}


@app.post("/removeadmin")
async def remove_admin(
    _: Annotated[bool, Depends(x_api_key_dependency)],
    remove_admin_form: RemoveAdminForm,
):
    await admin_collection.delete_one({"_id": remove_admin_form.open_id})
    await user_collection.delete_one({"_id": remove_admin_form.open_id})
    return {"status": 0}


# @app.get("/font/{filename}")
# async def get_font(filename: str, response: Response):
#     if not filename.endswith((".otf", ".ttf")):
#         raise HTTPException(status_code=400)

#     folder = Path(config.FONT_FOLDER)
#     path = (folder / filename).resolve()

#     if path.is_file() and str(path).startswith(str(folder.resolve())):
#         response.headers["Cache-Control"] = "public, max-age=31536000"
#         return FileResponse(path=path)
#     else:
#         raise HTTPException(status_code=404)
