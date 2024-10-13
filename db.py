from pymongo import MongoClient

from bson.objectid import ObjectId

# 连接到 MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"]  # 数据库名称
collection = db["mycollection"]  # 集合名称

# 自定义的 ID
custom_id = ObjectId("60c72b2f9b1d4c5c4a93dd63")  # 使用 ObjectId 格式

# # 插入文档时指定 _id
# document = {"_id": custom_id, "name": "Alice", "age": 30}

# try:
#     collection.insert_one(document)
#     print("文档插入成功，指定的 ID 为:", custom_id)
#     doc = collection.find({"_id": ObjectId(custom_id)})
#     print(doc.name)
# except Exception as e:
#     print("插入文档时出错:", e)

doc = collection.find({"_id": ObjectId(custom_id)})

print(next(doc).get("name"))
