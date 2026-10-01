# RCSForum Server

[English](README.md) | [简体中文](README.zh-CN.md)

The FastAPI backend for the `RCSForum` mini-app. It uses MongoDB to store users, topics, comments, likes, administrators, and check-in data, and authenticates users through the Feishu Open Platform.

## Features

- Exchange a temporary Feishu login code for a user identity
- API authentication based on server-side session tokens
- Topics, comments, likes, and deletion operations
- Anonymous posts and administrator permissions
- Image type validation, perceptual hashing, compression, and deduplication
- Static access to stickers and uploaded images
- Check-in online time tracking and leaderboards
- Asynchronous MongoDB data access

## Technology stack

- FastAPI
- MongoDB, Motor, PyMongo
- HTTPX
- Pillow, ImageHash, python-magic
- aiofiles

## Installation

A virtual environment is recommended:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install uvicorn
```

The system also needs `libmagic`. For example, on Debian/Ubuntu:

```bash
sudo apt install libmagic1
```

## MongoDB

Default connection:

```text
mongodb://localhost:27017/
```

The database is named `rcsforum`. Ensure MongoDB is running before starting the API.

## Configuration

`restful.py` reads runtime settings from `config.py`. The configuration must at least cover the following settings used by the current code:

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

Add other fields based on the actual `config.*` references in the code. Do not commit real `APP_SECRET` values, tokens, or production paths.

## Starting the server

```bash
uvicorn restful:app --host 0.0.0.0 --port 8000
```

For development, you can enable automatic reloading:

```bash
uvicorn restful:app --reload
```

Then point the API URL in the `RCSForum` client to this service.

## Data and files

The main collections include:

- `poster`
- `user`
- `admin`
- `checkin_collections`
- Periodically created `checkin_collection_*` collections

Uploaded images are stored in `UPLOAD_FOLDER`. The service validates MIME types, computes perceptual hashes, and compresses images; files with the same hash can be reused directly.

## Production deployment notes

- Use an HTTPS reverse proxy; do not expose the development server directly to the public internet.
- Store Open Platform secrets in environment variables or a secrets management system.
- Enable MongoDB authentication, access control, and backups.
- Configure upload directory permissions, size limits, request rate limits, and disk monitoring.
- Review CORS, trusted proxies, log privacy, and token expiration policies.
- Some exception paths in the current code return generic errors directly. Add tests and consistent error handling before deploying to production.

## License

See `LICENSE` in the repository.
