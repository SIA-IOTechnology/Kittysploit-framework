#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Détection endpoint GraphQL."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


PATHS = ["/graphql", "/graphiql", "/api/graphql", "/query", "/v1/graphql", "/altair"]


class Module(Scanner, Http_client):

    __info__ = {
        "name": "GraphQL detection",
        "description": "Detects GraphQL or GraphiQL endpoint (introspection risk).",
        "author": "KittySploit Team",
        "severity": "low",
        "modules": [],
        "tags": ["web", "scanner", "graphql", "api", "introspection"],
    }

    def run(self):
        for path in PATHS:
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 400):
                continue
            t = r.text.lower()
            if "graphql" in t or "graphiql" in t or "introspection" in t:
                self.set_info(severity="low", reason=f"GraphQL at {path}")
                return True
            if path in ("/graphql", "/query", "/api/graphql") and r.status_code == 400:
                post = self.http_request(method="POST", path=path, data='{"query": "{ __schema { types { name } } }"}', headers={"Content-Type": "application/json"})
                if post and post.status_code == 200 and ("data" in post.text or "__schema" in post.text):
                    self.set_info(severity="low", reason=f"GraphQL at {path} (introspection)")
                    return True
        return False
