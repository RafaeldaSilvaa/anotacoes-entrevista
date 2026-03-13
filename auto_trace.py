"""
Auto Trace - Instrumentação automática para Datadog APM

Instrumenta automaticamente funções, classes e módulos Python.

Uso simples:

import auto_trace

auto_trace.configure(service="payments-api")
auto_trace.instrument_caller()
"""

import functools
import inspect
import logging
import os
import platform
import random
import sys
import threading
from contextlib import contextmanager
from typing import Any, Callable, Dict, Optional, TypeVar, cast

from ddtrace import tracer as default_tracer

F = TypeVar("F", bound=Callable[..., Any])

logger = logging.getLogger(__name__)


class TraceConfig:
    """Configuração global do tracing"""

    def __init__(self) -> None:
        self._lock = threading.RLock()

        self.service: str = "python-service"

        self.enabled: bool = True

        self.sample_rate: float = 1.0

        self.send_args: bool = False
        self.send_arg_types: bool = False

        self.max_arg_len: int = 100
        self.max_args: int = 5

        self.exclude_specials: bool = True

        self.excluded_methods = {
            "__init__",
            "__repr__",
            "__str__",
            "__call__",
            "__getattr__",
            "__setattr__",
            "__delattr__",
            "__new__",
            "__class__",
            "__del__",
            "__dir__",
        }

        self.tracer = default_tracer

        self.instrument_generators = False

    def should_skip_method(self, name: str) -> bool:
        if self.exclude_specials and name in self.excluded_methods:
            return True
        return False


config = TraceConfig()


# ----------------------------
# CONFIGURAÇÃO
# ----------------------------


def configure(**kwargs: Any) -> None:
    """Atualiza configuração global"""
    with config._lock:
        for key, value in kwargs.items():
            if hasattr(config, key):
                setattr(config, key, value)
            else:
                raise AttributeError(f"Invalid config: {key}")


# ----------------------------
# UTILITÁRIOS
# ----------------------------


def safe_repr(obj: Any, max_len: int) -> str:
    try:
        r = repr(obj)
        if len(r) > max_len:
            return r[:max_len] + "..."
        return r
    except Exception:
        return "<unprintable>"


def _get_function_metadata(func: Callable) -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "name": func.__name__,
        "module": func.__module__,
        "qualname": func.__qualname__,
        "filename": None,
        "lineno": None,
    }

    try:
        meta["filename"] = inspect.getfile(func)
        meta["lineno"] = func.__code__.co_firstlineno
    except Exception:
        pass

    return meta


# ----------------------------
# TAGS
# ----------------------------


def _set_base_tags(span: Any, meta: Dict[str, Any]) -> None:
    span.set_tag("component", "auto_trace")

    span.set_tag("function.name", meta["name"])
    span.set_tag("function.module", meta["module"])
    span.set_tag("function.qualname", meta["qualname"])

    if meta["filename"]:
        span.set_tag("function.file", meta["filename"])

    if meta["lineno"]:
        span.set_tag("function.line", meta["lineno"])

    span.set_tag("process.pid", os.getpid())
    span.set_tag("python.version", platform.python_version())
    span.set_tag("thread.name", threading.current_thread().name)


def _set_args(span: Any, args: tuple, kwargs: Dict[str, Any]) -> None:
    if not config.send_args:
        return

    if config.send_arg_types:
        for i, arg in enumerate(args[: config.max_args]):
            span.set_tag(f"arg.{i}.type", type(arg).__name__)

        for k, v in list(kwargs.items())[: config.max_args]:
            span.set_tag(f"kwarg.{k}.type", type(v).__name__)

    else:
        for i, arg in enumerate(args[: config.max_args]):
            span.set_tag(f"arg.{i}", safe_repr(arg, config.max_arg_len))

        for k, v in list(kwargs.items())[: config.max_args]:
            span.set_tag(f"kwarg.{k}", safe_repr(v, config.max_arg_len))


def _set_exception(span: Any, exc: Exception) -> None:
    span.set_tag("error", 1)
    span.set_tag("error.type", type(exc).__name__)
    span.set_tag("error.msg", str(exc))


# ----------------------------
# WRAPPER
# ----------------------------


def _create_wrapper(func: Callable, meta: Dict[str, Any]) -> Callable:
    is_async = inspect.iscoroutinefunction(func)

    span_name = f"{meta['module']}.{meta['qualname']}"

    @functools.wraps(func)
    def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
        if not config.enabled:
            return func(*args, **kwargs)

        if config.sample_rate < 1 and random.random() > config.sample_rate:
            return func(*args, **kwargs)

        with config.tracer.trace(
            span_name,
            service=config.service,
            resource=span_name,
        ) as span:

            _set_base_tags(span, meta)
            _set_args(span, args, kwargs)

            try:
                return func(*args, **kwargs)
            except Exception as e:
                _set_exception(span, e)
                raise

    @functools.wraps(func)
    async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
        if not config.enabled:
            return await func(*args, **kwargs)

        with config.tracer.trace(
            span_name,
            service=config.service,
            resource=span_name,
        ) as span:

            _set_base_tags(span, meta)
            _set_args(span, args, kwargs)

            try:
                return await func(*args, **kwargs)
            except Exception as e:
                _set_exception(span, e)
                raise

    return async_wrapper if is_async else sync_wrapper


# ----------------------------
# INSTRUMENTAÇÃO
# ----------------------------


def instrument_function(func: F) -> F:
    if getattr(func, "_dd_traced", False):
        return func

    meta = _get_function_metadata(func)

    wrapped = _create_wrapper(func, meta)

    setattr(wrapped, "_dd_traced", True)

    return cast(F, wrapped)


def instrument_class(cls: type) -> None:
    for name, member in list(cls.__dict__.items()):
        if config.should_skip_method(name):
            continue

        if isinstance(member, staticmethod):
            setattr(cls, name, staticmethod(instrument_function(member.__func__)))

        elif isinstance(member, classmethod):
            setattr(cls, name, classmethod(instrument_function(member.__func__)))

        elif inspect.isfunction(member):
            setattr(cls, name, instrument_function(member))


def instrument_module(module: Any) -> None:
    module_name = module.__name__

    for name, obj in vars(module).items():
        if inspect.isfunction(obj) and obj.__module__ == module_name:
            setattr(module, name, instrument_function(obj))

        elif inspect.isclass(obj) and obj.__module__ == module_name:
            instrument_class(obj)


def instrument_caller() -> None:
    frame = inspect.currentframe()

    if not frame:
        return

    caller = frame.f_back

    if not caller:
        return

    module = inspect.getmodule(caller)

    if not module:
        module = sys.modules["__main__"]

    instrument_module(module)


# ----------------------------
# CONTEXT MANAGER
# ----------------------------


@contextmanager
def tracing_disabled():
    prev = config.enabled
    config.enabled = False

    try:
        yield
    finally:
        config.enabled = prev
