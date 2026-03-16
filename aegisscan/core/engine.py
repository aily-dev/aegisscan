"""
Core async engine for AegisScan
"""
import asyncio
import logging
from typing import Dict, List, Optional, Callable, Any
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import time


class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Task:
    """Represents a task in the engine"""
    id: str
    func: Callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    status: TaskStatus = TaskStatus.PENDING
    result: Any = None
    error: Optional[Exception] = None
    created_at: float = field(default_factory=time.time)
    completed_at: Optional[float] = None
    retries: int = 0
    max_retries: int = 3


class EventBus:
    """Central event bus for component communication"""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._logger = logging.getLogger(__name__)
    
    def subscribe(self, event_type: str, callback: Callable):
        """Subscribe to an event type"""
        if event_type not in self._subscribers:
            self._subscribers[event_type] = []
        self._subscribers[event_type].append(callback)
    
    def unsubscribe(self, event_type: str, callback: Callable):
        """Unsubscribe from an event type"""
        if event_type in self._subscribers:
            try:
                self._subscribers[event_type].remove(callback)
            except ValueError:
                pass
    
    async def publish(self, event_type: str, data: Any = None):
        """Publish an event"""
        if event_type in self._subscribers:
            for callback in self._subscribers[event_type]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(data)
                    else:
                        callback(data)
                except Exception as e:
                    self._logger.error(f"Error in event callback: {e}")


class RateLimiter:
    """Rate limiter for request throttling"""
    
    def __init__(self, max_requests: int = 10, time_window: float = 1.0):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = deque()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire permission to make a request"""
        async with self._lock:
            now = time.time()
            # Remove old requests outside the time window
            while self.requests and self.requests[0] < now - self.time_window:
                self.requests.popleft()
            
            # Check if we're at the limit
            if len(self.requests) >= self.max_requests:
                sleep_time = self.time_window - (now - self.requests[0])
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                    # Clean up again after sleep
                    while self.requests and self.requests[0] < now - self.time_window:
                        self.requests.popleft()
            
            self.requests.append(time.time())


class TaskQueue:
    """Priority-based task queue"""
    
    def __init__(self):
        self._queue = deque()
        self._lock = asyncio.Lock()
    
    async def put(self, task: Task, priority: int = 0):
        """Add a task to the queue with priority"""
        async with self._lock:
            self._queue.append((priority, task))
            self._queue = deque(sorted(self._queue, key=lambda x: x[0], reverse=True))
    
    async def get(self) -> Optional[Task]:
        """Get the next task from the queue"""
        async with self._lock:
            if self._queue:
                _, task = self._queue.popleft()
                return task
            return None
    
    async def empty(self) -> bool:
        """Check if queue is empty"""
        async with self._lock:
            return len(self._queue) == 0
    
    async def size(self) -> int:
        """Get queue size"""
        async with self._lock:
            return len(self._queue)


class AsyncEngine:
    """Main async engine for AegisScan"""
    
    def __init__(self, max_workers: int = 10, rate_limit: int = 10, time_window: float = 1.0):
        self.max_workers = max_workers
        self.rate_limiter = RateLimiter(rate_limit, time_window)
        self.task_queue = TaskQueue()
        self.event_bus = EventBus()
        self.tasks: Dict[str, Task] = {}
        self.workers: List[asyncio.Task] = []
        self.running = False
        self._logger = logging.getLogger(__name__)
        self._task_counter = 0
        self._lock = asyncio.Lock()
    
    async def start(self):
        """Start the engine"""
        if self.running:
            return
        
        self.running = True
        self.workers = [
            asyncio.create_task(self._worker(f"worker-{i}"))
            for i in range(self.max_workers)
        ]
        self._logger.info(f"Engine started with {self.max_workers} workers")
    
    async def stop(self):
        """Stop the engine"""
        self.running = False
        # Wait for all workers to finish
        if self.workers:
            await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers = []
        self._logger.info("Engine stopped")
    
    async def submit(self, func: Callable, *args, priority: int = 0, max_retries: int = 3, **kwargs) -> str:
        """Submit a task to the engine"""
        async with self._lock:
            self._task_counter += 1
            task_id = f"task-{self._task_counter}"
        
        task = Task(
            id=task_id,
            func=func,
            args=args,
            kwargs=kwargs,
            max_retries=max_retries
        )
        
        self.tasks[task_id] = task
        await self.task_queue.put(task, priority)
        await self.event_bus.publish("task.submitted", task)
        
        return task_id
    
    async def _worker(self, worker_name: str):
        """Worker coroutine that processes tasks"""
        while self.running:
            try:
                task = await self.task_queue.get()
                if task is None:
                    await asyncio.sleep(0.1)
                    continue
                
                await self._execute_task(task)
            except Exception as e:
                self._logger.error(f"Worker {worker_name} error: {e}")
                await asyncio.sleep(0.1)
    
    async def _execute_task(self, task: Task):
        """Execute a single task"""
        task.status = TaskStatus.RUNNING
        await self.event_bus.publish("task.started", task)
        
        try:
            # Apply rate limiting
            await self.rate_limiter.acquire()
            
            # Execute the task
            if asyncio.iscoroutinefunction(task.func):
                result = await task.func(*task.args, **task.kwargs)
            else:
                result = task.func(*task.args, **task.kwargs)
            
            task.result = result
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            await self.event_bus.publish("task.completed", task)
            
        except Exception as e:
            task.error = e
            task.retries += 1
            
            if task.retries < task.max_retries:
                task.status = TaskStatus.PENDING
                await self.task_queue.put(task, priority=0)
                await self.event_bus.publish("task.retry", task)
            else:
                task.status = TaskStatus.FAILED
                task.completed_at = time.time()
                await self.event_bus.publish("task.failed", task)
                self._logger.error(f"Task {task.id} failed after {task.retries} retries: {e}")
    
    async def wait_for_task(self, task_id: str, timeout: Optional[float] = None) -> Task:
        """Wait for a task to complete"""
        start_time = time.time()
        
        while True:
            task = self.tasks.get(task_id)
            if task and task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
                return task
            
            if timeout and (time.time() - start_time) > timeout:
                raise asyncio.TimeoutError(f"Task {task_id} timed out")
            
            await asyncio.sleep(0.1)
    
    def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID"""
        return self.tasks.get(task_id)
    
    async def cancel_task(self, task_id: str):
        """Cancel a task"""
        task = self.tasks.get(task_id)
        if task and task.status == TaskStatus.PENDING:
            task.status = TaskStatus.CANCELLED
            await self.event_bus.publish("task.cancelled", task)

