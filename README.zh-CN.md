# RCSForum Server

[English](README.md) | [简体中文](README.zh-CN.md)


`RCSForum` 小程序的 FastAPI 后端。服务使用 MongoDB 存储用户、主题、评论、点赞、管理员和签到数据，并通过飞书开放平台完成用户身份认证。

## 功能

- 飞书临时登录码换取用户身份
- 基于服务端会话令牌的接口认证
- 主题、评论、点赞和删除操作
- 匿名发帖与管理员权限
- 图片类型校验、感知哈希、压缩和去重
- 贴纸与上传图片静态访问
- 签到在线时长和排行榜
- 异步 MongoDB 数据访问

## 技术栈

- FastAPI
- MongoDB、Motor、PyMongo
- HTTPX
- Pillow、ImageHash、python-magic
- aiofiles

## 安装

建议使用虚拟环境：

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install uvicorn
```

系统还需要安装 `libmagic`。例如在 Debian/Ubuntu 上：

```bash
sudo apt install libmagic1
```

## MongoDB

默认连接：

```text
mongodb://localhost:27017/
```

数据库名称为 `rcsforum`。启动 API 前请确保 MongoDB 正在运行。

## 配置

`restful.py` 从 `config.py` 读取运行参数。配置至少需要覆盖当前代码使用的以下项目：

```python
APP_ID = "replace-me"
APP_SECRET = "replace-me"

LOG_PATH = "./logs/rcsforum.log"
UPLOAD_FOLDER = "./data/uploads"
STICKER_FOLDER = "./data/stickers"

EXPIRE_DURATION = 7 * 24 * 60 * 60
WEAK_EXPIRE_DURATION = 30 * 24 * 60 * 60
KEEP_ALIVE_INTERVAL = 30
MAX_IMAGE_SIZE = 10 * 1024 * 1024
```

请根据实际代码中的 `config.*` 引用补齐其他字段。不要提交真实的 `APP_SECRET`、令牌或生产路径。

## 启动

```bash
uvicorn restful:app --host 0.0.0.0 --port 8000
```

开发时可以启用自动重载：

```bash
uvicorn restful:app --reload
```

然后将 `RCSForum` 客户端中的 API 地址指向该服务。

## 数据与文件

主要集合包括：

- `poster`
- `user`
- `admin`
- `checkin_collections`
- 按周期创建的 `checkin_collection_*`

上传图片保存在 `UPLOAD_FOLDER`。服务会验证 MIME 类型、计算感知哈希并压缩图片；相同哈希的文件可直接复用。

## 生产部署注意事项

- 使用 HTTPS 反向代理，不要直接把开发服务器暴露到公网。
- 将开放平台密钥放入环境变量或秘密管理系统。
- 为 MongoDB 启用认证、访问控制和备份。
- 配置上传目录权限、大小限制、请求频率限制和磁盘监控。
- 检查 CORS、可信代理、日志隐私和令牌过期策略。
- 当前代码中部分异常路径直接返回通用错误，生产部署前应补充测试和统一错误处理。

## License

请参阅仓库中的 `LICENSE`。
