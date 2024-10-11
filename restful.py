from flask import Flask, request
from flask_restful import Api, Resource
import threading
import requests
import logging
import signal
import asyncio


def get_app_access_token():
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
            time_to_live = max(float(data["expire"]) - 10.0, 10.0)
            app.config["APP_ACCESS_TOKEN"] = data["app_access_token"]
            app.logger.info(
                f"Successfully update app access token, next update is {time_to_live} seconds later."
            )
            return time_to_live
        else:
            app.logger.error("Failed update app access token: ", res)
            return False

    except Exception as e:
        app.logger.error("Failed update app access token: ", e)
        return False


class CheckIn(Resource):
    def post(self):
        json_data = request.get_json()
        print(json_data)
        return {"message": "message"}


class Login(Resource):
    def post(self):
        print(request.get_json())
        print(app.config["APP_ACCESS_TOKEN"])


if __name__ == "__main__":
    app = Flask(__name__)
    app.config.from_pyfile("./config.py")
    app.logger.setLevel(app.config.get("LOG_LEVEL", logging.INFO))

    api = Api(app)
    api.add_resource(CheckIn, "/checkin")
    api.add_resource(Login, "/login")

    stop_event = asyncio.Event()  # 用来控制协程的停止

    async def update_app_token():
        ttl = get_app_access_token()
        while ttl:
            await asyncio.sleep(ttl)
            ttl = get_app_access_token()

    async def run_flask():
        app.run(host="0.0.0.0", port=5000, debug=True)

    async def main():
        # 使用 gather 同时运行 Flask 和 token 更新逻辑
        await asyncio.gather(run_flask(), update_app_token(), stop_event.wait())

    def shutdown():
        # 当接收到信号时，触发 stop_event 的停止
        app.logger.info("Shutting down...")
        stop_event.set()

    # 监听系统信号 SIGINT 和 SIGTERM，注册到 shutdown 函数
    signal.signal(signal.SIGINT, lambda sig, frame: shutdown())
    signal.signal(signal.SIGTERM, lambda sig, frame: shutdown())

    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        app.logger.info("Program exited")
