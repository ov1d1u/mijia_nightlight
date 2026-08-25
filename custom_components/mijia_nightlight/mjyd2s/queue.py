import asyncio

class OutQueue():
    def __init__(self):
        self._queue = asyncio.Queue()
        self._items_by_class = {}
        self._lock = asyncio.Lock()

    async def put(self, item):
        async with self._lock:
            self._items_by_class[type(item)] = item
            await self._queue.put(item)

    async def get(self):
        while True:
            item = await self._queue.get()
            item_class = type(item)

            async with self._lock:
                if self._items_by_class.get(item_class) is item:
                    del self._items_by_class[item_class]
                    return item

    def qsize(self):
        return self._queue.qsize()

    def empty(self):
        return self._queue.empty()