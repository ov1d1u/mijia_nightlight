import asyncio

class OutQueue():
    def __init__(self):
        self._queue = asyncio.Queue()
        self._items_by_class = {}

    async def put(self, item):
        item_class = type(item)
        if item_class in self._items_by_class:
            existing_item = self._items_by_class[item_class]
            self._queue._queue.remove(existing_item)
            del self._items_by_class[item_class]

        await self._queue.put(item)
        self._items_by_class[item_class] = item

    async def get(self):
        item = await self._queue.get()
        item_class = type(item)
        if item_class in self._items_by_class:
            del self._items_by_class[item_class]
        return item

    def qsize(self):
        return self._queue.qsize()

    def empty(self):
        return self._queue.empty()