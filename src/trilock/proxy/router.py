"""Namespacing and fan-out: one downstream surface over N upstream servers.

Tools and prompts are namespaced ``<server>.<name>``. Server names are
validated to contain no dot (see `trilock.config`), so splitting on the *first*
dot recovers the route unambiguously even though SEP-986 permits dots inside a
tool name.

Resources are addressed by opaque URI, which cannot be namespaced without
rewriting it and breaking the identifier. Instead the router keeps a routing
table built from the aggregated listings, and falls back to probing upstreams
in a deterministic order for URIs it has not seen (which is normal for
templated resources).

Aggregation is failure-tolerant by design: an upstream that is down or
erroring is skipped with a log, never propagated as a failure of the whole
listing. A proxy that goes dark because one of five servers is restarting is a
worse outcome than a listing that is briefly short.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, TypeVar, cast

import anyio
import mcp_types as types

from trilock import log
from trilock.proxy.upstream import Upstream, UpstreamPool

_log = log.get("proxy.router")

NAMESPACE_SEP: Final[str] = "."
MAX_TOOL_NAME_LEN: Final[int] = 128
MAX_LIST_PAGES: Final[int] = 100
"""Pagination guard: a misbehaving upstream must not spin the aggregator forever."""

ProgressCallback = Callable[[float, float | None, str | None], Awaitable[None]]

_T = TypeVar("_T")


class RouteError(ValueError):
    """A downstream name does not resolve to a known upstream tool or prompt."""


@dataclass(frozen=True, slots=True)
class Route:
    """A downstream-visible name split back into its upstream parts."""

    server: str
    name: str

    @property
    def qualified(self) -> str:
        return f"{self.server}{NAMESPACE_SEP}{self.name}"


def qualify(server: str, name: str) -> str:
    """The downstream-visible name for `name` on `server`."""
    return f"{server}{NAMESPACE_SEP}{name}"


def split_qualified(qualified: str) -> Route:
    """Recover the route from a downstream-visible name.

    Splits on the first separator: server names may not contain a dot, so
    everything after it belongs to the upstream name even if that name has
    dots of its own.
    """
    server, sep, name = qualified.partition(NAMESPACE_SEP)
    if not sep or not server or not name:
        raise RouteError(
            f"{qualified!r} is not a namespaced name; expected '<server>{NAMESPACE_SEP}<name>'"
        )
    return Route(server=server, name=name)


def strip_reserved_meta(meta: types.RequestParamsMeta | None) -> types.RequestParamsMeta | None:
    """Forward application `_meta` upstream, minus the entries the session owns.

    The progress token is re-minted by the upstream session (we bridge progress
    with a callback instead), and the reserved ``io.modelcontextprotocol/*``
    keys are supplied by the SDK per connection — echoing either would put two
    authorities on the same field.
    """
    if not meta:
        return None
    forwarded = cast(
        "types.RequestParamsMeta",
        {
            key: value
            for key, value in meta.items()
            if key != "progress_token" and not str(key).startswith("io.modelcontextprotocol/")
        },
    )
    return forwarded or None


class Router:
    """Aggregates and routes between the downstream server and the upstream pool."""

    def __init__(self, pool: UpstreamPool) -> None:
        self.pool = pool
        self._resource_owner: dict[str, str] = {}
        """URI -> upstream name, learned from resources/list."""

    # -- fan-out helpers -------------------------------------------------

    def _available(self) -> list[Upstream]:
        """Ready upstreams, in a stable order so routing is reproducible."""
        return [
            self.pool.upstreams[name]
            for name in sorted(self.pool.upstreams)
            if self.pool.upstreams[name].available
        ]

    async def _gather(
        self, fetch: Callable[[Upstream], Awaitable[Sequence[_T]]], what: str
    ) -> list[_T]:
        """Run `fetch` against every ready upstream, tolerating individual failures."""
        collected: dict[str, Sequence[_T]] = {}

        async def one(upstream: Upstream) -> None:
            try:
                collected[upstream.name] = await fetch(upstream)
            except Exception as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    raise
                _log.warning(
                    "upstream omitted from listing",
                    extra={
                        "server": upstream.name,
                        "listing": what,
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                )
                upstream.request_reconnect(f"{what} failed: {type(exc).__name__}")

        async with anyio.create_task_group() as tg:
            for upstream in self._available():
                tg.start_soon(one, upstream)
        return [item for name in sorted(collected) for item in collected[name]]

    @staticmethod
    async def _paginate(
        fetch: Callable[[str | None], Awaitable[tuple[Sequence[_T], str | None]]],
    ) -> list[_T]:
        """Drain every page of an upstream listing.

        Trilock returns one unpaginated listing downstream: the aggregate has no
        single cursor space, and a cursor minted by one upstream is meaningless
        to another.
        """
        items: list[_T] = []
        cursor: str | None = None
        for _ in range(MAX_LIST_PAGES):
            page, cursor = await fetch(cursor)
            items.extend(page)
            if cursor is None:
                return items
        _log.warning("listing truncated at the pagination guard", extra={"pages": MAX_LIST_PAGES})
        return items

    # -- tools -----------------------------------------------------------

    async def list_tools(self) -> types.ListToolsResult:
        """The union of every ready upstream's tools, namespaced."""

        async def fetch(upstream: Upstream) -> Sequence[types.Tool]:
            async def page(cursor: str | None) -> tuple[Sequence[types.Tool], str | None]:
                result = await upstream.client().list_tools(cursor=cursor)
                return result.tools, result.next_cursor

            return [_rename(tool, upstream.name) for tool in await self._paginate(page)]

        return types.ListToolsResult(tools=await self._gather(fetch, "tools/list"))

    def resolve(self, qualified: str) -> tuple[Upstream, str]:
        """Map a downstream tool or prompt name to (upstream, upstream name)."""
        route = split_qualified(qualified)
        return self.pool[route.server], route.name

    async def call_tool(
        self,
        qualified: str,
        arguments: dict[str, Any] | None,
        *,
        meta: types.RequestParamsMeta | None = None,
        progress_callback: Any = None,
    ) -> types.CallToolResult:
        """Execute a namespaced tool on its upstream."""
        upstream, name = self.resolve(qualified)
        return await upstream.client().call_tool(
            name,
            arguments,
            progress_callback=progress_callback,
            meta=strip_reserved_meta(meta),
        )

    # -- prompts ---------------------------------------------------------

    async def list_prompts(self) -> types.ListPromptsResult:
        async def fetch(upstream: Upstream) -> Sequence[types.Prompt]:
            async def page(cursor: str | None) -> tuple[Sequence[types.Prompt], str | None]:
                result = await upstream.client().list_prompts(cursor=cursor)
                return result.prompts, result.next_cursor

            return [
                prompt.model_copy(update={"name": qualify(upstream.name, prompt.name)})
                for prompt in await self._paginate(page)
            ]

        return types.ListPromptsResult(prompts=await self._gather(fetch, "prompts/list"))

    async def get_prompt(
        self,
        qualified: str,
        arguments: dict[str, str] | None,
        *,
        meta: types.RequestParamsMeta | None = None,
    ) -> types.GetPromptResult:
        upstream, name = self.resolve(qualified)
        return await upstream.client().get_prompt(name, arguments, meta=strip_reserved_meta(meta))

    # -- resources -------------------------------------------------------

    async def list_resources(self) -> types.ListResourcesResult:
        async def fetch(upstream: Upstream) -> Sequence[types.Resource]:
            async def page(cursor: str | None) -> tuple[Sequence[types.Resource], str | None]:
                result = await upstream.client().list_resources(cursor=cursor)
                return result.resources, result.next_cursor

            resources = await self._paginate(page)
            for resource in resources:
                self._resource_owner.setdefault(str(resource.uri), upstream.name)
            return resources

        return types.ListResourcesResult(resources=await self._gather(fetch, "resources/list"))

    async def list_resource_templates(self) -> types.ListResourceTemplatesResult:
        async def fetch(upstream: Upstream) -> Sequence[types.ResourceTemplate]:
            async def page(
                cursor: str | None,
            ) -> tuple[Sequence[types.ResourceTemplate], str | None]:
                result = await upstream.client().list_resource_templates(cursor=cursor)
                return result.resource_templates, result.next_cursor

            return await self._paginate(page)

        return types.ListResourceTemplatesResult(
            resource_templates=await self._gather(fetch, "resources/templates/list")
        )

    def resource_candidates(self, uri: str) -> list[Upstream]:
        """Upstreams to try for `uri`: the known owner first, then the rest in order."""
        owner = self._resource_owner.get(uri)
        candidates = self._available()
        if owner is None:
            return candidates
        return [u for u in candidates if u.name == owner] + [
            u for u in candidates if u.name != owner
        ]

    async def read_resource(
        self, uri: str, *, meta: types.RequestParamsMeta | None = None
    ) -> types.ReadResourceResult:
        """Read a resource, learning its owner on first success."""
        forwarded = strip_reserved_meta(meta)
        errors: list[str] = []
        for upstream in self.resource_candidates(uri):
            try:
                result = await upstream.client().read_resource(uri, meta=forwarded)
            except Exception as exc:
                if isinstance(exc, anyio.get_cancelled_exc_class()):
                    raise
                errors.append(f"{upstream.name}: {type(exc).__name__}: {exc}")
                continue
            self._resource_owner[uri] = upstream.name
            return result
        raise RouteError(
            f"no upstream served resource {uri!r}" + (f" ({'; '.join(errors)})" if errors else "")
        )


def _rename(tool: types.Tool, server: str) -> types.Tool:
    """Namespace a tool, preserving every other field including ``_meta``."""
    qualified = qualify(server, tool.name)
    if len(qualified) > MAX_TOOL_NAME_LEN:
        _log.warning(
            "namespaced tool name exceeds the SEP-986 length guidance",
            extra={"server": server, "tool": tool.name, "length": len(qualified)},
        )
    return tool.model_copy(update={"name": qualified})


def namespaced_names(tools: Iterable[types.Tool]) -> Mapping[str, Route]:
    """Index a namespaced listing by downstream name. Used by policy and pinning."""
    return {tool.name: split_qualified(tool.name) for tool in tools}
