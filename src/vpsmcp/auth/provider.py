"""Resource server and authorization server in one ASGI app, on one origin."""
from __future__ import annotations

from fastmcp.server.auth import RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier
from pydantic import AnyHttpUrl
from starlette.routing import Route

from ..settings import SCOPES, Settings
from .keys import KeyStore
from .oauth import AuthorizationServer
from .store import Store


class FleetAuthProvider(RemoteAuthProvider):
    def __init__(self, settings: Settings, store: Store, keys: KeyStore, audit):
        self.s = settings
        self.as_server = AuthorizationServer(settings, store, keys, audit)
        verifier = JWTVerifier(
            public_key=keys.public_pem,
            issuer=settings.issuer,
            audience=settings.resource_url,
            algorithm="RS256",
        )
        super().__init__(
            token_verifier=verifier,
            authorization_servers=[AnyHttpUrl(settings.public_url)],
            base_url=settings.public_url,
            scopes_supported=list(SCOPES),
            resource_name="VPS Fleet MCP",
            # scopes advertised in the 401 challenge
            challenge_scopes=["fleet.read", "fleet.exec", "fleet.write"],
        )

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        routes.extend(self.as_server.routes())
        return routes
