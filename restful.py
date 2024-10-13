from flask import Flask, request, jsonify
from flask_restful import Api, Resource
import threading
import requests
import logging
import time
import math
import uuid


from pymongo import MongoClient
from bson.objectid import ObjectId

client = MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]
poster = db["poster"]
user = db["user"]
comment = db["comment"]

app = Flask(__name__)
app.config.from_pyfile("./config.py")
app.logger.setLevel(app.config.get("LOG_LEVEL", logging.INFO))


def retry_with_limit(func):
    def wrapper():
        res = func()
        if res.status_code == 429:
            limit, to_wait = (
                float(res.headers["x-ogw-ratelimit-limit"]),
                float(res.headers["x-ogw-ratelimit-reset"]),
            )
            app.logger.warning(
                f"api {func.__name__} reaches the frequency limitation. Limit: {limit}, Time to recover: {to_wait}"
            )
            handle = threading.Timer(to_wait, wrapper)
            handle.daemon = True
            handle.start()
        else:
            return res

    return wrapper


token_lock = threading.Lock()


def renew_app_access_token():
    try:
        res = requests.post(
            url="https://open.feishu.cn/open-apis/auth/v3/app_access_token/internal",
            headers={"Content-Type": "application/json; charset=utf-8"},
            json={
                "app_id": app.config.get("APP_ID"),
                "app_secret": app.config.get("APP_SECRET"),
            },
        )
        data = res.json()
        if res.status_code == 200 and data["code"] == 0:
            time_to_live = max(float(data["expire"]) - 300.0, 300.0)
            with token_lock:
                app.config["APP_ACCESS_TOKEN"] = data["app_access_token"]
            app.logger.info(
                f"Successfully update app access token, next update is {time_to_live} seconds later."
            )
            return time_to_live
        else:
            app.logger.error(f"Failed update app access token: {res.text}")
            return False

    except Exception as e:
        app.logger.error(f"Failed update app access token: {e}")
        return False


def renew_app_token():
    ttl = renew_app_access_token()
    while ttl:
        time.sleep(ttl)
        ttl = renew_app_access_token()


threading.Thread(
    target=renew_app_token, name="renew app access token", daemon=True
).start()


class CheckIn(Resource):
    def post(self):
        json_data = request.get_json()
        print(json_data)
        return {"message": "message"}


class Login(Resource):
    def post(self):
        req_json = request.get_json()
        with token_lock:
            app_access_token = app.config.get("APP_ACCESS_TOKEN")
        app_access_token = f"Bearer {app_access_token}"

        @retry_with_limit
        def user_access_token_req():
            return requests.post(
                url="https://open.feishu.cn/open-apis/authen/v1/oidc/access_token",
                headers={
                    "Authorization": app_access_token,
                    "Content-Type": "application/json; charset=utf-8",
                },
                json={
                    "grant_type": "authorization_code",
                    "code": req_json["code"],
                },
            )

        res = user_access_token_req()
        body = res.json()
        if not (res.status_code == 200 and body["code"] == 0):
            app.logger.error(f"Failed to get user access token, resp: {res.text}")
            return jsonify({"status": 1})
        user_access_token = body["data"]["access_token"]
        user_access_token = f"Bearer {user_access_token}"

        @retry_with_limit
        def user_info_req():
            return requests.get(
                url="https://open.feishu.cn/open-apis/authen/v1/user_info",
                headers={
                    "Authorization": user_access_token,
                },
            )

        res = user_info_req()
        body = res.json()
        if not (res.status_code == 200 and body["code"] == 0):
            app.logger.error(f"Failed to get user info, resp: {res.text}")
            return jsonify({"status": 2})
        data = body["data"]
        name, avatar, id = data["name"], data["avatar_url"], data["open_id"]

        cid = uuid.uuid4()
        current_user = user.find_one({"_id": ObjectId(id)})

        if not current_user:
            user.insert_one(
                {"_id": ObjectId(id), "cid": cid, "time": math.floor(time.time())}
            )
        else:
            user.update_one(
                {"_id": ObjectId(id)},
                {"$set": {"cid": cid, "time": math.floor(time.time())}},
            )

        return jsonify({"name": name, "avatar": avatar, "id": cid})


api = Api(app)
api.add_resource(CheckIn, "/checkin")
api.add_resource(Login, "/login")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
