import asyncio
import random

cnt = 0


async def add():
    global cnt
    for _ in range(1000):
        num = cnt
        await asyncio.sleep(random.randrange(1, 999) / 100000)
        num += 1
        cnt = num


async def main():
    await asyncio.gather(add(), add())


asyncio.run(main())

print(cnt)
