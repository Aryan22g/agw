"""Cross-language conformance: Python must reproduce the Go corpus exactly.

This is the test that makes a second SDK trustworthy. The corpus at
pkg/ags1/vectors/ags1-v1.json is generated from the Go implementation and pins
the canonical body, content digest, signature input, signature base and
signature for concrete requests. If Python and Go disagree about a single byte,
a signature minted by one is rejected by the other -- and that failure surfaces
in production as an opaque "signature invalid", not as anything diagnosable.
"""

import base64
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ags_sdk import canonical, digest, jcs, keys, protocol  # noqa: E402
from ags_sdk.errors import AGS1Error  # noqa: E402
from ags_sdk.parser import parse_signature_input  # noqa: E402
from ags_sdk.signer import sign_request, verify_request  # noqa: E402

CORPUS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "..", "pkg", "ags1", "vectors", "ags1-v1.json"
)


def load_corpus():
    with open(CORPUS_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


class ConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = load_corpus()
        cls.vectors = cls.corpus["vectors"]

    def test_corpus_loads(self):
        self.assertEqual(self.corpus["profile"], "AGS1")
        self.assertEqual(self.corpus["tag"], "agw-sig-v1")
        self.assertGreater(len(self.vectors), 0)

    def test_signing_matches_go_byte_for_byte(self):
        """Every positive vector must re-sign to identical bytes."""
        checked = 0
        for vector in self.vectors:
            if not vector["verify"]["accepted"]:
                continue

            with self.subTest(vector=vector["name"]):
                private = keys.load_private_key(vector["privateKey"])

                body = vector.get("body") or ""
                headers, signed_body, meta = sign_request(
                    method=vector["method"],
                    url=vector["url"],
                    tenant_id=vector["tenantId"],
                    agent_id=vector["agentId"],
                    private_key=private,
                    body=body.encode("utf-8") if body else None,
                    content_type=vector.get("contentType") or None,
                    key_id=vector["keyId"],
                    nonce_value=vector["nonce"],
                    request_id=vector["requestId"],
                    traceparent=vector["traceparent"],
                    created=vector["created"],
                )

                self.assertEqual(
                    meta["signature_base"].decode("utf-8"),
                    vector["signatureBase"],
                    "signature base differs from the Go implementation",
                )
                self.assertEqual(
                    headers[protocol.HEADER_SIGNATURE_INPUT],
                    vector["signatureInput"],
                )
                self.assertEqual(
                    headers[protocol.HEADER_SIGNATURE],
                    vector["signature"],
                    "signature bytes differ from the Go implementation",
                )

                if vector.get("contentDigest"):
                    self.assertEqual(
                        headers[protocol.HEADER_CONTENT_DIGEST], vector["contentDigest"]
                    )
                if vector.get("canonicalBody"):
                    self.assertEqual(signed_body.decode("utf-8"), vector["canonicalBody"])

                checked += 1

        self.assertGreater(checked, 0, "no positive vectors were checked")

    def test_verification_matches_corpus(self):
        """Accept every positive vector and reject every negative one."""
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                public = keys.load_public_key(vector["publicKey"])

                body = (vector.get("canonicalBody") or "").encode("utf-8")
                headers = dict(vector["headers"])
                headers[protocol.HEADER_SIGNATURE_INPUT] = vector["signatureInput"]
                headers[protocol.HEADER_SIGNATURE] = vector["signature"]

                if vector["verify"]["accepted"]:
                    result = verify_request(
                        vector["method"], vector["url"], headers, body,
                        public, now=vector["verify"]["nowUnix"],
                    )
                    self.assertEqual(result["key_id"], vector["keyId"])
                else:
                    with self.assertRaises(
                        AGS1Error,
                        msg=f"vector {vector['name']} should have been rejected "
                            f"({vector['verify']['reason']})",
                    ):
                        verify_request(
                            vector["method"], vector["url"], headers, body,
                            public, now=vector["verify"]["nowUnix"],
                        )

    def test_jcs_matches_corpus(self):
        for vector in self.vectors:
            if not vector.get("canonicalBody") or vector.get("contentType") != "application/json":
                continue
            if not vector["verify"]["accepted"]:
                continue

            with self.subTest(vector=vector["name"]):
                got = jcs.canonicalize_bytes(vector["body"].encode("utf-8"))
                self.assertEqual(got.decode("utf-8"), vector["canonicalBody"])

    def test_digest_matches_corpus(self):
        for vector in self.vectors:
            if not vector.get("contentDigest") or not vector["verify"]["accepted"]:
                continue
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    digest.compute(vector["canonicalBody"].encode("utf-8")),
                    vector["contentDigest"],
                )

    def test_key_id_matches_corpus(self):
        for vector in self.vectors:
            with self.subTest(vector=vector["name"]):
                public = keys.load_public_key(vector["publicKey"])
                self.assertEqual(keys.key_id(public), vector["keyId"])


class ThumbprintTest(unittest.TestCase):
    """RFC 8037 Appendix A.3 known-answer test.

    kid is how a signature names the credential it should be checked against,
    so every AGS1 SDK must derive this exact string from this exact key.
    """

    def test_rfc8037_known_answer(self):
        import hashlib

        x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        expected = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"

        got = base64.urlsafe_b64encode(
            hashlib.sha256(keys.thumbprint_input(x)).digest()
        ).decode("ascii").rstrip("=")

        self.assertEqual(got, expected)

    def test_thumbprint_input_is_exact(self):
        x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        self.assertEqual(
            keys.thumbprint_input(x).decode("utf-8"),
            '{"crv":"Ed25519","kty":"OKP","x":"%s"}' % x,
        )

    def test_forged_kid_rejected(self):
        _, public, _ = keys.generate()
        jwk = keys.public_key_to_jwk(public)
        jwk["kid"] = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        with self.assertRaises(AGS1Error):
            keys.jwk_to_public_key(jwk)


class ProfileTest(unittest.TestCase):
    """Profile rules that must hold independently of the corpus."""

    def test_alg_on_wire_rejected(self):
        with self.assertRaises(AGS1Error):
            parse_signature_input(
                'sig1=("@method" "@authority" "@path" "@query" "x-agent-id" '
                '"x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent")'
                ';created=1750000000;keyid="k";nonce="sT9nUq2vXmK4pLzR8bYwCd"'
                ';tag="agw-sig-v1";alg="ed25519"'
            )

    def test_foreign_tag_rejected(self):
        with self.assertRaises(AGS1Error):
            parse_signature_input(
                'sig1=("@method" "@authority" "@path" "@query" "x-agent-id" '
                '"x-tenant-id" "x-request-id" "x-agent-signature-version" "traceparent")'
                ';created=1750000000;keyid="k";nonce="sT9nUq2vXmK4pLzR8bYwCd";tag="other"'
            )

    def test_truncated_component_list_rejected(self):
        with self.assertRaises(Exception):
            canonical.validate_covered_components(["@method", "@path"], False)

    def test_replay_ttl_outlasts_acceptance_window(self):
        self.assertGreater(
            protocol.REPLAY_TTL_SECONDS,
            protocol.ACCEPTANCE_WINDOW_SECONDS,
            "a nonce that expires while its request is still valid is replayable",
        )

    def test_query_absent_signs_as_question_mark(self):
        self.assertEqual(canonical.canonical_query(""), "?")
        self.assertEqual(canonical.canonical_query("a=1"), "?a=1")

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaises(Exception):
            jcs.canonicalize_bytes(b'{"a":1,"a":2}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
