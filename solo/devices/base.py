import struct
from abc import abstractmethod
from typing import Any, Mapping, Protocol, Literal

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.base import Certificate
from fido2.attestation import Attestation
from fido2.client import Fido2Client, ClientPin
from fido2.ctap1 import Ctap1
from fido2.ctap2 import Ctap2, CredentialManagement
from fido2.hid import CTAPHID, CtapHidDevice
from fido2.utils import hmac_sha256
from fido2.webauthn import (
    AttestationObject,
    AuthenticatorAttestationResponse,
    CollectedClientData,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    PublicKeyCredentialParameters,
    PublicKeyCredentialType,
)

from .. import helpers


# class ExchangeFuntion(Protocol):
#     def __call__(self, cmd: int, addr: int = ..., data: bytes | bytearray = ..., /) -> float:
#         ...

class ExchangeCallback(Protocol):
    def __call__(
        self,
        cmd: int,
        addr: int = 0,
        data: bytes | bytearray = b"A" * 16,
        /
    ) -> bytes:
        ...


# Base class
# Currently some methods are implemented here since they are the same in both devices.
class SoloClient(Protocol):
    origin: str
    host: str
    user_id: bytes
    # exchange: Callable[[int, int, bytes | bytearray], bytes]
    exchange: ExchangeCallback
    do_reboot: bool
    dev: CtapHidDevice
    client: Fido2Client | None
    ctap1: Ctap1
    ctap2: Ctap2 | None
    # device = None
    # fido_client = None
    # hid_device = None
    # bootloader = False
    # solo = False

    def __init__(self) -> None:
        self.origin = "https://example.org"
        self.host = "example.org"
        self.user_id = b"they"
        self.do_reboot = True

    def set_reboot(self, val: bool) -> None:
        """option to reboot after programming"""
        self.do_reboot = val

    @abstractmethod
    def reboot(self) -> None:
        pass

    @abstractmethod
    def find_device(self, dev: CtapHidDevice | None = None, solo_serial: str | None = None) -> CtapHidDevice:
        pass

    @abstractmethod
    def get_current_hid_device(self) -> CtapHidDevice:
        """Return current device class for CTAPHID interface if available."""
        pass

    @abstractmethod
    def get_current_fido_client(self) -> Fido2Client | None:
        """Return current fido2 client if available."""
        pass

    def send_data_hid(self, cmd: int, data: bytes | str) -> bytes:
        if isinstance(data, str):
            data = struct.pack("%dB" % len(data), *[ord(x) for x in data])
        with helpers.Timeout(1.0) as event:
            return self.get_current_hid_device().call(cmd, data, event)

    @abstractmethod
    def bootloader_version(self) -> tuple[int, int, int] | tuple[Literal[0], Literal[0], int]:
        pass

    @abstractmethod
    def solo_version(self) -> bytes | tuple[int, int, int]:
        pass

    @abstractmethod
    def get_rng(self, num: int = 0) -> None:
        pass

    def wink(self) -> None:
        self.send_data_hid(CTAPHID.WINK, b"")

    def ping(self, data: str = "pong"):
        return self.send_data_hid(CTAPHID.PING, data)

    def reset(self) -> None:
        Ctap2(self.get_current_hid_device()).reset()

    def change_pin(self, old_pin: str, new_pin: str) -> None:
        if self.ctap2 is None:
            raise ValueError("CTAP2 not available")
        pin = ClientPin(self.ctap2)
        pin.change_pin(old_pin, new_pin)

    def set_pin(self, new_pin: str) -> None:
        if self.ctap2 is None:
            raise ValueError("CTAP2 not available")
        pin = ClientPin(self.ctap2)
        pin.set_pin(new_pin)

    def make_credential(self) -> Certificate:
        client = self.get_current_fido_client()
        if client is None:
            raise ValueError("FIDO client not available")
        rp = PublicKeyCredentialRpEntity("example site", self.host)
        user = PublicKeyCredentialUserEntity("example user", self.user_id)
        challenge = b"Y2hhbGxlbmdl"
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
        result: AuthenticatorAttestationResponse = client.make_credential(options)
        attest: AttestationObject = result.attestation_object
        data: CollectedClientData = result.client_data
        try:
            attest.verify(data.hash)  # type: ignore
        except AttributeError:
            verifier = Attestation.for_type(attest.fmt)
            verifier().verify(attest.att_stmt, attest.auth_data, data.hash)
        print("Register valid")
        x5c = attest.att_stmt["x5c"][0]
        cert = x509.load_der_x509_certificate(x5c, default_backend())

        return cert

    def cred_mgmt(self, pin: str) -> CredentialManagement:
        if self.ctap2 is None:
            raise ValueError("CTAP2 client not available")
        client_pin = ClientPin(self.ctap2)
        token = client_pin.get_pin_token(pin)
        _ctap2 = Ctap2(self.get_current_hid_device())
        return CredentialManagement(_ctap2, client_pin.protocol, token)

    @abstractmethod
    def enter_solo_bootloader(self) -> None:
        """
        If solo is configured as solo hacker or something similar,
        this command will tell the token to boot directly to the bootloader
        so it can be reprogrammed
        """
        pass

    @abstractmethod
    def enter_bootloader_or_die(self) -> None:
        pass

    @abstractmethod
    def is_solo_bootloader(self) -> bool:
        """For now, solo bootloader could be the NXP bootrom on Solo v2."""
        pass

    def program_kbd(self, cmd: Mapping[int, Any]) -> Mapping[int, Any]:
        _ctap2 = Ctap2(self.get_current_hid_device())
        return _ctap2.send_cbor(0x51, cmd)

    def sign_hash(self, credential_id: str, dgst: bytes, pin: str) -> Mapping[int, Any]:
        _ctap2 = Ctap2(self.get_current_hid_device())
        client_pin = ClientPin(_ctap2)
        if pin:
            pin_token = client_pin.get_pin_token(pin)
            pin_auth = hmac_sha256(pin_token, dgst)[:16]
            return _ctap2.send_cbor(
                0x50,
                {1: dgst, 2: {"id": credential_id, "type": "public-key"}, 3: pin_auth},
            )
        else:
            return _ctap2.send_cbor(0x50, {1: dgst, 2: {"id": credential_id, "type": "public-key"}})

    @abstractmethod
    def program_file(self, name: str) -> bytes:
        pass
