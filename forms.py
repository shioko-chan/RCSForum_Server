from pydantic import BaseModel
from typing import List, Optional


class TempCodeForm(BaseModel):
    code: str


class CreatePosterForm(BaseModel):
    title: str
    content: str
    is_anonymous: bool
    images: List[str]


class LikeTopicForm(BaseModel):
    pid: str


class UnlikeTopicForm(BaseModel):
    pid: str


class DeleteTopicForm(BaseModel):
    pid: str


class CreateCommentForm(BaseModel):
    content: str
    is_anonymous: bool
    pid: str
    images: List[str]
    index_1: Optional[int] = None


class LikeCommentForm(BaseModel):
    pid: str
    index1: int
    index2: Optional[int] = None


class UnlikeCommentForm(BaseModel):
    pid: str
    index1: int
    index2: Optional[int] = None


class DeleteCommentForm(BaseModel):
    pid: str
    index1: int
    index2: Optional[int] = None
