from flask import Flask, request
from flask_restful import Api, Resource

app = Flask(__name__)
api = Api(app)


class CheckIn(Resource):
    def post(self):
        json_data = request.get_json()
        print(json_data)
        return {"message": "fuck you"}


api.add_resource(CheckIn, "/checkin")

if __name__ == "__main__":
    app.run(debug=True)
