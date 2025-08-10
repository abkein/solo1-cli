# -*- coding: utf-8 -*-
#
# Copyright 2019 SoloKeys Developers
#
# Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
# http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
# http://opensource.org/licenses/MIT>, at your option. This file may not be
# copied, modified, or distributed except according to those terms.
#
# isort:skip_file


import binascii
import hashlib
import secrets

from fido2.webauthn import (
    AttestationObject,
    AuthenticatorAttestationResponse,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
)
import solo.client


def make_credential(
    host: str = "solokeys.dev",
    user_id: str = "they",
    serial: str | None = None,
    prompt: str | None = "Touch your authenticator to generate a credential...",
    output: bool = True,
    udp: bool = False,
) -> bytes:
    client = solo.client.find(solo_serial=serial, udp=udp).get_current_fido_client()
    if client is None:
        raise RuntimeError("No FIDO client found")

    # client.user_id = user_id
    # client.host = host
    client.origin = f"https://{host}"

    rp = PublicKeyCredentialRpEntity("Example RP", host)
    user = PublicKeyCredentialUserEntity("A. User", user_id.encode())
    challenge = secrets.token_bytes(32)

    if prompt is not None:
        print(prompt)

    PKCT = PublicKeyCredentialType("public-key")
    pub_key_cred_params = [
        PublicKeyCredentialParameters(PKCT, -8),
        PublicKeyCredentialParameters(PKCT, -7)
    ]

    options = PublicKeyCredentialCreationOptions(
        rp,
        user,
        challenge,
        pub_key_cred_params,
    )

    attestation_object = client.make_credential(options).attestation_object

    credential = attestation_object.auth_data.credential_data
    if credential is None:
        raise RuntimeError("No credential data found")

    credential_id = credential.credential_id

    if output:
        print(credential_id.hex())

    return credential_id


def simple_secret(
    credential_id: bytes,
    secret_input: str,
    host: str = "solokeys.dev",
    serial: str | None = None,
    prompt: str | None = "Touch your authenticator to generate a response...",
    output: bool = True,
    udp: bool = False,
):
    client = solo.client.find(solo_serial=serial, udp=udp).get_current_fido_client()
    if client is None:
        raise RuntimeError("No FIDO client found")

    # client.host = host
    client.origin = f"https://{host}"
    # client.user_id = user_id

    credential_id = binascii.a2b_hex(credential_id)

    challenge = secrets.token_bytes(32)

    h = hashlib.sha256()
    h.update(secret_input.encode())
    salt = h.digest()

    if prompt:
        print(prompt)

    PKCD = PublicKeyCredentialDescriptor(PublicKeyCredentialType("public-key"), credential_id)

    PKCRO = PublicKeyCredentialRequestOptions(challenge=challenge, rp_id=host, allow_credentials=[PKCD], extensions={"hmacGetSecret": {"salt1": salt}})

    assertion = client.get_assertion(PKCRO).get_response(0)

    extension_results = assertion.extension_results
    if extension_results is None:
        raise RuntimeError("No extension results found")

    output1 = extension_results["hmacGetSecret"]["output1"]

    if output:
        print(output1.hex())

    return output1
