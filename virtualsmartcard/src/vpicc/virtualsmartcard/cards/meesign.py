from tarfile import DEFAULT_FORMAT
from xmlrpc.client import Boolean
import grpc
from enum import Enum
from doc.virtualsmartcard.utils import APDU

from virtualsmartcard.SWutils import SwError, SW
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

        self.pins = {PinType.ADMIN_PIN_REFERENCE: Pin(),
                     PinType.AUTH_PIN_REFERENCE: Pin(),
                     PinType.SING_PIN_REFERENCE: Pin()
                     }

    def powerUp(self):
        print("Powering up...")

    def execute(self, msg):
        if isinstance(msg, str):
            apdu = map(ord, msg)
        else:
            apdu = list(msg)

    def create_task(self, apdu:APDU, name: str, group_id: bytes, data: bytes):
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

    def retries_left(self, apdu: APDU):
        """ Returns the number of verification attempts left for the requested PIN
        
        :param apdu: The request apdu
        """
        if apdu.P1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        requested_pin_type = apdu.P2
        req_pin = self.pins.get(requested_pin_type)
        if req_pin is None:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        # send req_pin.attempts_left() out at the zeroth byte

    def verify_pin(self, apdu: APDU):
        """
        Verifies the suplied PIN
        
        """
        if apdu.P1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        if apdu.LC != apdu.getIncomingLength() or apdu.LC > Pin.PIN_MAX_SIZE:
            raise SwError(SW["SW_WRONG_LENGTH"])

        requested_pin_type = apdu.P2

        req_pin = self.pins.get(requested_pin_type)
        if req_pin is None:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        if req_pin.attempts_left() == 0:
            raise SwError(SW["SW_PIN_BLOCKED"])

        if req_pin.attempts_left() <= 0:
            raise SwError(SW["SW_WRONG_PIN_X_TRIES_LEFT"])

        # return ok


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
