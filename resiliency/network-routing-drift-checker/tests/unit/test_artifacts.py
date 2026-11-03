# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
"""S3 artifact error handling and intent-read outcomes (security-compliance §5)."""

import io

import pytest
from botocore.exceptions import ClientError, EndpointConnectionError

from drift_core.artifacts import ArtifactError, Artifacts, read_intent


class S3:
    def __init__(self, get_exc=None, put_exc=None, body=b"version: 1\n"):
        self.get_exc, self.put_exc, self.body = get_exc, put_exc, body

    def get_object(self, Bucket, Key):  # noqa: N803
        if self.get_exc:
            raise self.get_exc
        return {"Body": io.BytesIO(self.body), "VersionId": "v1"}

    def put_object(self, **_):
        if self.put_exc:
            raise self.put_exc


def denied(code):
    return ClientError({"Error": {"Code": code}}, "Op")


def test_read_intent_outcomes():
    assert read_intent(S3(), "b", "k") == ("found", "version: 1\n", "v1", None)
    assert read_intent(S3(get_exc=denied("NoSuchKey")), "b", "k")[0] == "absent"
    assert read_intent(S3(get_exc=denied("AccessDenied")), "b", "k") == ("unreadable", None, None, "AccessDenied")
    assert read_intent(S3(get_exc=EndpointConnectionError(endpoint_url="x")), "b", "k")[0] == "unreadable"
    assert read_intent(S3(body=b"\xff\xfe"), "b", "k")[0] == "unreadable"


def test_artifact_errors_raise_typed_error():
    a = Artifacts(S3(put_exc=denied("AccessDenied")), "b", "r1")
    with pytest.raises(ArtifactError):
        a.put_json("x.json", {})
    with pytest.raises(ArtifactError):
        Artifacts(S3(get_exc=denied("NoSuchKey")), "b", "r1").get_json("x.json")
    assert a.uri("x.json") == "s3://b/runs/r1/x.json"
