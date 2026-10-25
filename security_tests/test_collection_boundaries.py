"""Security regressions using real config loaders, authorization, and storage."""
import sys
from types import SimpleNamespace

import numpy as np
import pytest
import yaml
from fastapi.testclient import TestClient

from chromadb.api.collection_configuration import (
    load_collection_configuration_from_json,
    load_create_collection_configuration_from_json,
    load_update_collection_configuration_from_json,
)
from chromadb.auth import AuthzAction
from chromadb.config import Settings
from chromadb.errors import NotFoundError
from chromadb.server.fastapi import FastAPI
from chromadb.utils.embedding_functions.sentence_transformer_embedding_function import (
    SentenceTransformerEmbeddingFunction,
)


@pytest.mark.parametrize(
    "loader",
    [
        load_collection_configuration_from_json,
        load_create_collection_configuration_from_json,
        load_update_collection_configuration_from_json,
    ],
)
@pytest.mark.parametrize(
    "kwargs",
    [
        {"trust_remote_code": True},
        {"trust_remote_code": "false"},
        {"model_kwargs": {"trust_remote_code": True}},
        {"tokenizer_kwargs": {"trust_remote_code": True}},
        {"config_kwargs": {"trust_remote_code": True}},
    ],
)
def test_serialized_embedding_configuration_cannot_enable_remote_code(
    monkeypatch, loader, kwargs
):
    constructed = []
    monkeypatch.setitem(
        sys.modules,
        "sentence_transformers",
        SimpleNamespace(
            SentenceTransformer=lambda **values: constructed.append(values)
        ),
    )
    monkeypatch.setattr(SentenceTransformerEmbeddingFunction, "models", {})
    config = {
        "embedding_function": {
            "type": "known",
            "name": "sentence_transformer",
            "config": {
                "model_name": "test-model",
                "device": "cpu",
                "normalize_embeddings": False,
                "kwargs": kwargs,
            },
        }
    }
    with pytest.raises(ValueError, match="trust_remote_code"):
        loader(config)
    assert constructed == []
    config["embedding_function"]["config"]["kwargs"] = {"trust_remote_code": False}
    assert loader(config)["embedding_function"] is not None
    assert len(constructed) == 1


@pytest.fixture(
    params=["chromadb.api.segment.SegmentAPI", "chromadb.api.rust.RustBindingsAPI"]
)
def server(request):
    identities = [
        {
            "id": name,
            "tenant": name + "-tenant",
            "databases": [name + "-database"],
            "tokens": [name + "-test-token"],
        }
        for name in ("alice", "bob")
    ]
    settings = Settings(
        chroma_api_impl=request.param,
        anonymized_telemetry=False,
        chroma_server_authn_provider="chromadb.auth.token_authn.TokenAuthenticationServerProvider",
        chroma_server_authn_credentials=yaml.safe_dump({"users": identities}),
        chroma_server_authz_provider="chromadb.auth.simple_rbac_authz.SimpleRBACAuthorizationProvider",
        chroma_server_authz_config=yaml.safe_dump(
            {
                "users": [{"id": name, "role": "writer"} for name in ("alice", "bob")],
                "roles_mapping": {
                    "writer": {"actions": [action.value for action in AuthzAction]}
                },
            }
        ),
    )
    instance = FastAPI(settings)
    collections = {}
    client_started = False
    try:
        for identity in identities:
            tenant, database = identity["tenant"], identity["databases"][0]
            instance._api.create_tenant(tenant)
            instance._api.create_database(database, tenant=tenant)
            collection = instance._api.create_collection(
                identity["id"] + "-collection", tenant=tenant, database=database
            )
            instance._api._add(
                ids=["seed"],
                collection_id=collection.id,
                embeddings=[np.array([1.0, 0.0], dtype=np.float32)],
                tenant=tenant,
                database=database,
            )
            collections[identity["id"]] = collection
        with TestClient(instance.app()) as client:
            client_started = True
            yield instance, client, collections
    finally:
        if not client_started:
            instance._system.stop()


@pytest.mark.parametrize("version,scope", [("v1", ""), ("v2", "alice"), ("v2", "bob")])
@pytest.mark.parametrize(
    "operation,payload",
    [
        ("get", {"ids": ["seed"]}),
        ("query", {"query_embeddings": [[1.0, 0.0]], "n_results": 1}),
        ("count", None),
        ("add", {"ids": ["injected"], "embeddings": [[1.0, 0.0]]}),
        ("update", {"ids": ["seed"], "embeddings": [[0.0, 1.0]]}),
        ("upsert", {"ids": ["seed"], "embeddings": [[0.0, 1.0]]}),
        ("delete", {"ids": ["seed"]}),
        ("modify", {"new_name": "hijacked-collection"}),
    ],
)
def test_collection_requests_cannot_cross_identity_scope(
    server, version, scope, operation, payload
):
    instance, client, collections = server
    victim = collections["bob"]
    prefix = "/api/" + version
    if version == "v2":
        prefix += f"/tenants/{scope}-tenant/databases/{scope}-database"
    url = prefix + "/collections/" + str(victim.id)
    if operation != "modify":
        url += "/" + operation
    headers = {"Authorization": "Bearer alice-test-token"}
    method = (
        "GET" if operation == "count" else "PUT" if operation == "modify" else "POST"
    )
    response = client.request(
        method,
        url,
        headers=headers,
        **({"json": payload} if payload is not None else {}),
    )
    assert response.status_code in (403, 404), response.text
    assert (
        instance._api._count(victim.id, tenant="bob-tenant", database="bob-database")
        == 1
    )
    own_prefix = (
        "/api/v1"
        if version == "v1"
        else "/api/v2/tenants/alice-tenant/databases/alice-database"
    )
    own = client.get(
        own_prefix + "/collections/" + str(collections["alice"].id) + "/count",
        headers=headers,
    )
    assert own.status_code == 200, own.text
    assert own.json() == 1


def test_collection_metadata_and_database_scope_are_checked(server):
    instance, client, collections = server
    victim = collections["bob"]
    with pytest.raises(NotFoundError):
        instance._api.get_collection_by_id(
            victim.id, tenant="alice-tenant", database="alice-database"
        )
    with pytest.raises(NotFoundError):
        instance._api.get_collection_by_id(
            victim.id, tenant="bob-tenant", database="alice-database"
        )
    assert (
        instance._api.get_collection_by_id(
            victim.id, tenant="bob-tenant", database="bob-database"
        ).id
        == victim.id
    )
