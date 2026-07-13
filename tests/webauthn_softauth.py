#!/usr/bin/env python3
# A minimal software WebAuthn authenticator scripted with `cryptography`, for
# local tests (spec 12/14.2). It produces registration attestations and
# authentication assertions that py_webauthn==1.8.0 verifies, plus knobs for the
# negative cases the suite needs (UV-absent, wrong-origin, counter-regression).
#
# Scope (pinned): ES256 only (COSE -7, EC P-256), attestation format "none". It
# is NOT a general FIDO2 stack; anything beyond this goes to the manual runbook.
#
# ruff: noqa: PLR6301

import hashlib
import json
import os
import struct

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url

ZERO_AAGUID = bytes(16)  # platform authenticators report all-zero AAGUID under "none"


class SoftwareAuthenticator:
	def __init__(self, rp_id, origin, aaguid=ZERO_AAGUID):
		self.rp_id = rp_id
		self.origin = origin
		self.aaguid = aaguid
		self._private_key = ec.generate_private_key(ec.SECP256R1())
		self.credential_id = os.urandom(32)
		self.sign_count = 0

	def cose_public_key(self):
		# COSE_Key for an EC2 / P-256 / ES256 public key.
		numbers = self._private_key.public_key().public_numbers()
		x = numbers.x.to_bytes(32, "big")
		y = numbers.y.to_bytes(32, "big")
		return cbor2.dumps({1: 2, 3: -7, -1: 1, -2: x, -3: y})

	def _authenticator_data(self, uv, include_attested_cred, sign_count):
		rp_id_hash = hashlib.sha256(self.rp_id.encode("utf-8")).digest()
		flags = 0x01  # UP
		if uv:
			flags |= 0x04  # UV
		if include_attested_cred:
			flags |= 0x40  # AT
		data = rp_id_hash + bytes([flags]) + struct.pack(">I", sign_count)
		if include_attested_cred:
			data += self.aaguid + struct.pack(">H", len(self.credential_id)) + self.credential_id + self.cose_public_key()
		return data

	def _client_data_json(self, ceremony_type, challenge_b64url, origin):
		return json.dumps(
			{"type": ceremony_type, "challenge": challenge_b64url, "origin": origin},
			separators=(",", ":"),
		).encode("utf-8")

	def create(self, challenge_b64url, *, uv=True, origin=None):
		# navigator.credentials.create() -- returns a RegistrationCredential dict.
		origin = self.origin if origin is None else origin
		client_data = self._client_data_json("webauthn.create", challenge_b64url, origin)
		auth_data = self._authenticator_data(uv=uv, include_attested_cred=True, sign_count=self.sign_count)
		attestation_object = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": auth_data})
		return {
			"id": bytes_to_base64url(self.credential_id),
			"rawId": bytes_to_base64url(self.credential_id),
			"response": {
				"clientDataJSON": bytes_to_base64url(client_data),
				"attestationObject": bytes_to_base64url(attestation_object),
			},
			"type": "public-key",
		}

	def get(self, challenge_b64url, *, uv=True, origin=None, sign_count=None, user_handle=None):
		# navigator.credentials.get() -- returns an AuthenticationCredential dict.
		# By default the counter increments by one; pass sign_count to force a
		# specific (e.g. non-increasing) value for the regression negative case.
		origin = self.origin if origin is None else origin
		if sign_count is None:
			self.sign_count += 1
			sign_count = self.sign_count
		else:
			self.sign_count = sign_count
		client_data = self._client_data_json("webauthn.get", challenge_b64url, origin)
		auth_data = self._authenticator_data(uv=uv, include_attested_cred=False, sign_count=sign_count)
		client_data_hash = hashlib.sha256(client_data).digest()
		signature = self._private_key.sign(auth_data + client_data_hash, ec.ECDSA(hashes.SHA256()))
		response = {
			"clientDataJSON": bytes_to_base64url(client_data),
			"authenticatorData": bytes_to_base64url(auth_data),
			"signature": bytes_to_base64url(signature),
		}
		if user_handle is not None:
			response["userHandle"] = bytes_to_base64url(user_handle)
		return {
			"id": bytes_to_base64url(self.credential_id),
			"rawId": bytes_to_base64url(self.credential_id),
			"response": response,
			"type": "public-key",
		}
