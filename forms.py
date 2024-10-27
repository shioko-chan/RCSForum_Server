from pydantic import BaseModel
from typing import List, Optional
from bson.objectid import ObjectId


class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v, _) -> "PyObjectId":
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


class TempCodeForm(BaseModel):
    code: str


class CreatePosterForm(BaseModel):
    title: str
    content: str
    is_anonymous: bool
    images: List[str]


class LikeTopicForm(BaseModel):
    pid: PyObjectId


class UnlikeTopicForm(BaseModel):
    pid: PyObjectId


class DeleteTopicForm(BaseModel):
    pid: PyObjectId


class CreateCommentForm(BaseModel):
    content: str
    is_anonymous: bool
    pid: PyObjectId
    images: List[str]
    index_1: Optional[int] = None


class LikeCommentForm(BaseModel):
    pid: PyObjectId
    index_1: int
    index_2: Optional[int] = None


class UnlikeCommentForm(BaseModel):
    pid: PyObjectId
    index_1: int
    index_2: Optional[int] = None


class DeleteCommentForm(BaseModel):
    pid: PyObjectId
    index_1: int
    index_2: Optional[int] = None


class CreateAdminForm(BaseModel):
    open_id: str


class RemoveAdminForm(BaseModel):
    open_id: str
