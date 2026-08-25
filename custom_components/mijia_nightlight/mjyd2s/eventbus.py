import asyncio
import logging

LOGGER = logging.getLogger(__name__)

class EventBus():
  def __init__(self):
    self.listeners = {}

  def add_listener(self, event_name, listener):
    if not self.listeners.get(event_name, None):
      self.listeners[event_name] = {listener}
    else:
      self.listeners[event_name].add(listener)

  def remove_listener(self, event_name, listener):
    if event_name not in self.listeners:
      return

    self.listeners[event_name].discard(listener)
    if len(self.listeners[event_name]) == 0:
      del self.listeners[event_name]

  def send(self, event_name, event_data=None):
    listeners = self.listeners.get(event_name, set())
    for listener in listeners:
      task = asyncio.create_task(listener(event_data))

      def _log_task_exception(completed_task):
        try:
          exception = completed_task.exception()
        except asyncio.CancelledError:
          return

        if exception is not None:
          LOGGER.error(
            "Event listener failed for %s",
            event_name,
            exc_info=(type(exception), exception, exception.__traceback__),
          )

      task.add_done_callback(_log_task_exception)