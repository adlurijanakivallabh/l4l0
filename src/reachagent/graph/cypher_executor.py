"""Cypher execution seam for the Neo4j backend (plan §12, §13).

The Neo4j store never speaks bolt itself. It emits Cypher and hands it to a
:class:`CypherExecutor`; the only production executor,
:class:`MCPCypherExecutor`, drives the **same** ``neo4j-cypher`` MCP server the
agent uses (``uvx mcp-neo4j-cypher``) through the ``mcp`` *client* SDK. There is
no ``import neo4j`` anywhere in ReachAgent — "all Neo4j I/O goes through the MCP
tool" is a structural property, not a convention (CLAUDE.md §13).

The seam is an interface (:class:`CypherExecutor`) with two methods —
``read``/``write`` mapping one-to-one to the server's ``read_neo4j_cypher`` /
``write_neo4j_cypher`` tools — so the store depends on the contract, not the
transport. A test can substitute an in-memory executor without a live database.

The MCP client SDK is async and stdio-based; the store and its callers (pytest,
the future Coordinator) are synchronous. :class:`MCPCypherExecutor` bridges the
two by owning a background thread that runs one asyncio loop for the process
lifetime, keeping a single warm ``ClientSession`` open. Each ``read``/``write``
submits a coroutine to that loop and blocks for the JSON rows — so the ``uvx``
server is spawned once per executor, not once per query.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
from collections.abc import Mapping, Sequence
from concurrent.futures import Future
from contextlib import AbstractContextManager
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from types import TracebackType
    from typing import Self

# The neo4j-cypher MCP server and its bolt connection. Mirrors the ~/.claude.json
# server block so the executor drives the identical server the agent connects to.
_ENV_URI = "NEO4J_URI"
_ENV_USER = "NEO4J_USERNAME"
_ENV_PASSWORD = "NEO4J_PASSWORD"  # noqa: S105 — env var *name*, not a secret value
_DEFAULT_URI = "bolt://localhost:7687"
_DEFAULT_USER = "neo4j"

_READ_TOOL = "read_neo4j_cypher"
_WRITE_TOOL = "write_neo4j_cypher"

# Rows type: the MCP tools return a JSON array of row objects.
Row = Mapping[str, object]


@runtime_checkable
class CypherExecutor(Protocol):
    """The store's only view of Neo4j: run a Cypher statement, get rows back.

    ``read`` and ``write`` map to the ``neo4j-cypher`` MCP server's two tools.
    Both take a parameterized query (never string-interpolated — that is how the
    store keeps values, including anything sensitive, out of the query text) and
    return the result rows as plain dicts.
    """

    def read(self, query: str, params: Mapping[str, object] | None = None) -> list[Row]: ...

    def write(self, query: str, params: Mapping[str, object] | None = None) -> list[Row]: ...


def _rows_from_tool_result(result: object) -> list[Row]:
    """Parse an MCP ``CallToolResult`` into row dicts.

    The neo4j-cypher tools return their rows as a single ``TextContent`` whose
    text is a JSON array. A tool error surfaces as ``isError`` and is raised
    rather than silently returning no rows — a swallowed write failure would let
    the store believe a node landed when it did not.
    """
    is_error = getattr(result, "isError", False)
    content = getattr(result, "content", []) or []
    text = ""
    for chunk in content:
        chunk_text = getattr(chunk, "text", None)
        if chunk_text is not None:
            text += chunk_text
    if is_error:
        raise CypherExecutionError(text or "neo4j-cypher MCP tool reported an error")
    if not text.strip():
        return []
    parsed = json.loads(text)
    if isinstance(parsed, Mapping):
        return [parsed]
    if isinstance(parsed, Sequence):
        return [row for row in parsed if isinstance(row, Mapping)]
    return []


class CypherExecutionError(RuntimeError):
    """A Cypher statement failed at the MCP server / database."""


class MCPCypherExecutor(AbstractContextManager["MCPCypherExecutor"]):
    """A :class:`CypherExecutor` backed by the ``neo4j-cypher`` MCP server (§13).

    Use as a context manager so the ``uvx`` subprocess and its warm session are
    torn down deterministically::

        with MCPCypherExecutor() as ex:
            store = Neo4jGraphStore(ex)
            ...
    """

    def __init__(
        self,
        *,
        uri: str | None = None,
        username: str | None = None,
        password: str | None = None,
        command: str = "uvx",
        args: Sequence[str] = ("mcp-neo4j-cypher",),
    ) -> None:
        self._uri = uri or os.environ.get(_ENV_URI, _DEFAULT_URI)
        self._username = username or os.environ.get(_ENV_USER, _DEFAULT_USER)
        # Read-only-first discipline extends to config: no baked-in default
        # password. Absent credential is a loud failure at connect, never a guess.
        self._password = password if password is not None else os.environ.get(_ENV_PASSWORD)
        self._command = command
        self._args = list(args)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._session: object | None = None
        self._shutdown: asyncio.Event | None = None
        self._ready = threading.Event()
        self._start_error: BaseException | None = None

    # -- lifecycle --------------------------------------------------------

    def __enter__(self) -> Self:
        if self._password is None:
            raise CypherExecutionError(
                f"no Neo4j password: set ${_ENV_PASSWORD} (the neo4j-cypher MCP server "
                "needs it to connect) — refusing to guess a credential"
            )
        self._thread = threading.Thread(target=self._run_loop, name="mcp-cypher", daemon=True)
        self._thread.start()
        self._ready.wait()
        if self._start_error is not None:
            raise CypherExecutionError(
                f"could not start neo4j-cypher MCP session: {self._start_error}"
            )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        loop = self._loop
        shutdown = self._shutdown
        # Signal the driver coroutine to close the session in its *own* task —
        # the MCP client's anyio scopes must be exited by the task that entered
        # them, so teardown cannot happen from a second run_until_complete.
        if loop is not None and shutdown is not None:
            loop.call_soon_threadsafe(shutdown.set)
        if self._thread is not None:
            self._thread.join(timeout=10)

    def _run_loop(self) -> None:
        """Own one asyncio loop for the executor's lifetime on this thread.

        A single driver coroutine opens the session, signals ready, waits for the
        shutdown event, then closes — so open and close run in the same task.
        """
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._drive())
        finally:
            loop.close()

    async def _drive(self) -> None:
        from contextlib import AsyncExitStack

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._shutdown = asyncio.Event()
        params = StdioServerParameters(
            command=self._command,
            args=self._args,
            env={
                **os.environ,
                _ENV_URI: self._uri,
                _ENV_USER: self._username,
                _ENV_PASSWORD: self._password or "",
            },
        )
        try:
            async with AsyncExitStack() as stack:
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()
                self._session = session
                self._ready.set()
                await self._shutdown.wait()
        except BaseException as err:  # noqa: BLE001 — surfaced to __enter__ via _start_error
            if not self._ready.is_set():
                self._start_error = err
                self._ready.set()
            else:
                raise

    # -- CypherExecutor contract -----------------------------------------

    def read(self, query: str, params: Mapping[str, object] | None = None) -> list[Row]:
        return self._call(_READ_TOOL, query, params)

    def write(self, query: str, params: Mapping[str, object] | None = None) -> list[Row]:
        return self._call(_WRITE_TOOL, query, params)

    def _call(self, tool: str, query: str, params: Mapping[str, object] | None) -> list[Row]:
        loop = self._loop
        session = self._session
        if loop is None or session is None:
            raise CypherExecutionError("executor is not started; use it as a context manager")
        arguments: dict[str, object] = {"query": query}
        if params:
            arguments["params"] = dict(params)
        future: Future[object] = asyncio.run_coroutine_threadsafe(
            session.call_tool(tool, arguments),  # type: ignore[attr-defined]
            loop,
        )
        result = future.result(timeout=30)
        return _rows_from_tool_result(result)
