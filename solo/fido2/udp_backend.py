import socket
import typing

from fido2.hid.base import CtapHidConnection, HidDescriptor


class UdpCtapHidConnection(CtapHidConnection):
    descriptor: HidDescriptor
    sock: socket.socket
    remote: tuple[str, int]
    local: tuple[str, int]
    """CtapHidConnection implementation which uses an UDP channel"""

    def __init__(self, descriptor: HidDescriptor) -> None:
        self.descriptor = descriptor
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        descriptor_path = descriptor.path if isinstance(descriptor.path, str) else bytes(descriptor.path).decode("utf-8")
        self.remote, self.local = (
            (addr, int(port)) for [addr, port] in (host.split(":") for host in descriptor_path.split("<"))
        )
        self.sock.bind(self.local)
        self.sock.settimeout(5.0)

    def close(self) -> None:
        self.sock.close()

    def write_packet(self, data) -> None:
        self.sock.sendto(data, self.remote)

    def read_packet(self) -> bytes:
        data, host = self.sock.recvfrom(self.descriptor.report_size_out)
        return data


def open_connection(descriptor: HidDescriptor) -> UdpCtapHidConnection:
    return UdpCtapHidConnection(descriptor)


def get_descriptor(path: str) -> HidDescriptor:
    return HidDescriptor(
        path, 0x1234, 0x5678, 64, 64, "software test interface", "12345678"
    )


def list_descriptors() -> typing.Iterable[HidDescriptor]:
    return map(get_descriptor, ["localhost:8111<localhost:7112"])
