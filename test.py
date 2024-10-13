from quart import Quart, jsonify
import time
import asyncio

app = Quart(__name__)


@app.route("/")
async def root():
    await asyncio.sleep(10)
    return jsonify({"foo": "123"})


app.run()
