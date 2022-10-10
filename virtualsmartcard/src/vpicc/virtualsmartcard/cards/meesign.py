from tarfile import DEFAULT_FORMAT
from xmlrpc.client import Boolean
import grpc
from enum import Enum
import struct

from virtualsmartcard.utils import C_APDU
from virtualsmartcard.SmartcardSAM import SAM
from virtualsmartcard.SWutils import SwError, SW
from virtualsmartcard.VirtualSmartcard import Iso7816OS
from virtualsmartcard.cards.mpc_pb2 import SignRequest
from virtualsmartcard.cards.mpc_pb2_grpc import MPCStub
from virtualsmartcard.ConstantDefinitions import MAX_EXTENDED_LE


class MeesignOS(Iso7816OS):
    """
    This class implements a meesign virtual card that is used for Nextcloud authentication.
    The virtual card provides an interface between a meesign server and a webeid application.
    """

    INFINIT_EID_ATR = bytes([0x3b, 0xfe, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0x80, 0x31,
                             0x80, 0x66, 0x40, 0x90, 0xa5, 0x10, 0x2e, 0x10, 0x83, 0x01, 0x90, 0x00, 0xf2])

    def __init__(self, mf, sam, _meesign_url, maxle=MAX_EXTENDED_LE):
        # Iso7816OS.__init__(self, mf, sam, ins2handler, maxle)
        self.ins2handler = {
            0x20: self.SAM.verify,
            0x26: self.SAM.retries_left

        }
        self.atr = MeesignOS.INFINIT_EID_ATR
        self.meesign_url = _meesign_url

    def execute(self, msg):
        if isinstance(msg, str):
            apdu = map(ord, msg)
        else:
            apdu = list(msg)
        # TODO: try .. except..
        c = C_APDU(msg)
        return Iso7816OS.formatResult()

    def create_task(self, apdu: C_APDU, name: str, group_id: bytes, data: bytes):
        """
        Creates a new signing task, blocks, and sends signature back in the response APDU

        :param apdu: Apdu with the signing challenge request
        :param name: Name of the task
        :param group_id: Id of the signing group
        :param data: Data containing the signing challenge to be signed    
        """
        with grpc.insecure_channel(self.meesign_url) as channel:
            stub = MPCStub(channel)
            response = stub.Register(SignRequest(name, group_id, data))
        # TODO: finish
        print("Got response: " + response.message)


class Meesign_SAM(SAM):
    
    def __init__(self):
        self.pins = {
            PinType.ADMIN_PIN_REFERENCE: Pin(),
            PinType.AUTH_PIN_REFERENCE: Pin(),
            PinType.SING_PIN_REFERENCE: Pin()
        }

    def verify(self, p1, p2, data):
        """
        Verifies the suplied PIN
        """
        if p1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        # TODO: check lengths
        # if lc != apdu.getIncomingLength() or apdu.LC > Pin.PIN_MAX_SIZE:
        #    raise SwError(SW["SW_WRONG_LENGTH"])

        requested_pin_type = p2

        req_pin = self.pins.get(requested_pin_type)
        if req_pin is None:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        if req_pin.attempts_left() == 0:
            raise SwError(SW["SW_PIN_BLOCKED"])

        if req_pin.verify_pin(data) == False:
            raise SwError(SW["SW_WRONG_PIN_X_TRIES_LEFT"])

        return SW["NORMAL"], b""

    def retries_left(self, p1, p2, data):
        """ 
        Returns the number of verification attempts left for the requested PIN
        """
        if p1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        requested_pin_type = p2
        req_pin = self.pins.get(requested_pin_type)
        if req_pin is None:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        return SW["NORMAL"], format_unsigned_short(req_pin.attempts_left())


class Pin:
    """
    Represents a PIN instance
    """

    PIN_MAX_SIZE = 12
    DEFAULT_ATEMPT_COUNT = 3

    def __init__(self):
        self.attempts = Pin.DEFAULT_ATEMPT_COUNT

    def set_pin(self, new_pin: bytes):
        pass

    def change_pin(self, new_pin: bytes):
        pass

    def attempts_left(self) -> int:
        return self.attempts

    def verify_pin(self, pin) -> Boolean:
        self.attempts_left -= 1

        # FIXME: ar we caring about constant time comparison?
        result = pin == self.pin

        if result:
            self.attempts_left += 1

        return result


class InstructionType(Enum):
    """ 
    Holds instruction constants
    """
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


class PinType(Enum):
    """
    Holds pin types
    """
    AUTH_PIN_REFERENCE = 0x01
    SING_PIN_REFERENCE = 0x02
    ADMIN_PIN_REFERENCE = 0x03


def format_unsigned_short(num):
    return struct.pack(">H", num)
