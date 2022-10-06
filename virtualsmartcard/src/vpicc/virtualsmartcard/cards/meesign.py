import grpc
from enum import Enum

from virtualsmartcard.VirtualSmartcard import Iso7816OS
from virtualsmartcard.cards.mpc_pb2 import SignRequest
from virtualsmartcard.cards.mpc_pb2_grpc import MPCStub


class MeesignOS(Iso7816OS):
    """
    This class implements a meesign virtual card that is used for Nextcloud authentication.
    The virtual card provides an interface between a meesign server and a webeid application.
    """

    def __init__(self, _meesign_url):
        self.atr = b'\x3B\x8A\x80\x01\x80\x31\xF8\x73\xF7\x41\xE0\x82\x90' + \
                   b'\x00\x75'
        self.meesign_url = _meesign_url

        self.create_task("asd", b"123", b"321")

    def powerUp(self):
        print("Powering up...")

    def execute(self, msg):
        if isinstance(msg, str):
            apdu = map(ord, msg)
        else:
            apdu = list(msg)

    def create_task(self, name, group_id, data):
        with grpc.insecure_channel(self.meesign_url) as channel:
            stub = MPCStub(channel)
            response = stub.Register(SignRequest(name, group_id, data))
        print("Got response: " + response.message)


class Instruction(Enum):
    INS_VERIFY_PIN = 0x20
    INS_CHANGE_PIN = 0x24
    INS_UNBLOCK = 0x2C
    INS_RESET_RETRY_COUNTER = 0x2C
    INS_SELECT = 0xA4
    INS_READ_BINARY = 0xB0
    INS_UPDATE_BINARY = 0xD6
    INS_ERASE_BINARY = 0x0E
    INS_READ_RECORD = 0xB2
    INS_MANAGE_SECURITY_ENVIRONMENT = 0x22
    INS_AUTHENTICATE = 0x88
    INS_MUTUAL_AUTHENTICATE = 0x82
    INS_GET_CHALLENGE = 0x84
    INS_UPDATE_RECORD = 0xDC
    INS_APPEND_RECORD = 0xE2
    INS_GET_DATA = 0xCA
    INS_PUT_DATA = 0xDA
    INS_CREATE_FILE = 0xE0
    INS_DELETE_FILE = 0xE4
    INS_GENERATE_KEYPAIR = 0x01
    INS_PERFORM_SIGNATURE = 0x2A
    INS_GET_PUBLIC_KEY = 0x02
    INS_STORE_CERTIFICATE = 0x03
    INS_GET_CERTIFICATE = 0x04
    INS_GET_RESPONSE = 0xC0
    INS_SET_PIN = 0x22
    INS_PIN_RETRIES_LEFT = 0x26
