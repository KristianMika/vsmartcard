from multiprocessing.sharedctypes import Value
from xmlrpc.client import Boolean
import grpc
from enum import Enum
import struct
from datetime import datetime
import time
from Crypto.PublicKey import ECC

from virtualsmartcard.utils import C_APDU
from virtualsmartcard.SmartcardFilesystem import MF
from virtualsmartcard.SEutils import Security_Environment
from virtualsmartcard.SmartcardSAM import SAM
from virtualsmartcard.VirtualSmartcard import Iso7816OS
from virtualsmartcard.SWutils import SwError, SW
from virtualsmartcard.cards.mpc_pb2 import SignRequest, TaskRequest, Task
from virtualsmartcard.cards.mpc_pb2_grpc import MPCStub
from virtualsmartcard.ConstantDefinitions import MAX_EXTENDED_LE


class MeesignOS(Iso7816OS):
    """
    This class implements a meesign virtual card that is used for Nextcloud authentication.
    The virtual card provides an interface between a meesign server and a webeid application.
    """

    INFINIT_EID_ATR = bytes([0x3b, 0xfe, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0x80, 0x31,
                             0x80, 0x66, 0x40, 0x90, 0xa5, 0x10, 0x2e, 0x10, 0x83, 0x01, 0x90, 0x00, 0xf2])

    def __init__(self, mf, sam, _meesign_url, _group_id,  ins2handler=None, maxle=MAX_EXTENDED_LE):
        if not _group_id:
            raise ValueError("group_id not specified")
        Iso7816OS.__init__(self, mf, sam, ins2handler, maxle)
        self.ins2handler = {
            0x02: self.SAM.get_public_key,
            0x03: self.SAM.store_certificate,
            0x04: self.SAM.get_certificate,
            0x20: self.SAM.verify,
            0x26: self.SAM.retries_left,
            0x2A: self.SAM.perform_security_operation,
            0x88: self.SAM.authenticate,
            0xa4: self.mf.selectFile
        }
        self.atr = MeesignOS.INFINIT_EID_ATR

        sam.meesign_url = _meesign_url
        sam.group_id = _group_id
        sam.auth_pubkey = _group_id

    def execute(self, msg):
        return Iso7816OS.execute(self, msg)


class MeesignSE(Security_Environment):
    pass


class MeesignMF(MF):
    AID = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    def selectFile(self, p1, p2, data):
        if data == MeesignMF.AID:
            return SW["NORMAL"], b""
        else:
            return SW["ERR_FILENOTFOUND"], b""





class MeesignSAM(SAM):
    def __init__(self, mf=None):
        SAM.__init__(self, None, None, mf, default_se=MeesignSE)
        self.current_SE = self.default_se(self.mf, self)
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

        if len(data) > Pin.PIN_MAX_SIZE:
            raise SwError(SW["SW_WRONG_LENGTH"])

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

    def perform_security_operation(self, p1, p2, data):
        raise SwError(SW["ERR_NOTSUPPORTED"])

        parameters = (p1 << 8) | p2
        if parameters != 0x9E9A:
            raise SwError(SW["ERR_INCORRECTP1P2"])


    def get_certificate(self, p1, p2, data):
        if p1 == 0x01:
            return SW["NORMAL"], self.auth_cert
        elif p1 == 0x02:
            # TODO: implement signing?
            raise SwError(SW["ERR_NOTSUPPORTED"])
        else:
            raise SwError(SW["ERR_INCORRECTP1P2"])

    def store_certificate(self, p1, p2, data):
        if not self.pins.get(PinType.ADMIN_PIN_REFERENCE).is_validated():
            raise SwError(CustomSW.SW_PIN_VERIFICATION_REQUIRED)

        if p1 == 0x01:
            # TODO: data == cert?
            self.auth_cert = data
        elif p1 == 0x02:
            raise SwError(SW["ERR_NOTSUPPORTED"])
        else:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        self.pins.get(PinType.ADMIN_PIN_REFERENCE).reset()

    def get_public_key(self, p1, p2, data):
        key = None
        if p1 == Reference.AUTH_KEYPAIR_REFERENCE:
            key = self.auth_pubkey #TODO: store keys in a struct
        elif p1 == Reference.SIGNING_KEYPAIR_REFERENCE:
            # TODO: implement signing?
            raise SwError(SW["ERR_NOTSUPPORTED"])
        else:
            # TODO: not in the original applet
            raise SwError(SW["ERR_INCORRECTP1P2"])


        if p2 != Reference.GET_PUBLIC_KEY_REFERENCE:
            raise SwError(SW["ERR_INCORRECTP1P2"])
        return SW["NORMAL"], key


    def authenticate(self, p1, p2, data):
        if not self.pins.get(PinType.AUTH_PIN_REFERENCE).is_validated():
            raise SwError(CustomSW.SW_PIN_VERIFICATION_REQUIRED)

        curr_datetime = datetime.now().strftime('%d.%m.%Y, %H:%M:%S')
        task_id = self.__create_task("Nextcloud authentication request from " + curr_datetime, self.group_id, data)
        task = self.__wait_for_task(task_id)
        if task is None or task.status == Task.TaskStatus.FAILED:
            raise SwError(SW["ERR_NOINFO6A"]) #TODO: better error

        self.pins.get(PinType.AUTH_PIN_REFERENCE).reset()
        return SW["NORMAL"], task.data # TODO: task.data?

    def __create_task(self, name: str, group_id: bytes, data: bytes):
        """
        Creates a new signing task

        :param name: Name of the task
        :param group_id: Id of the signing group
        :param data: Data containing the signing challenge to be signed    
        """
        # TODO: self.meesign_url fix
        # TODO: try grpc.secure_channel()
        with grpc.insecure_channel("localhost:1337") as channel:
            stub = MPCStub(channel)
            response = stub.Sign(SignRequest(
                name=name, group_id=group_id, data=data))
        print("Got response: " + response.message)
        return response.id

    def __wait_for_task(self, task_id: bytes):
        MAX_ATTEMPTS = 20
        ATTEMPT_DELAY_S = 1
        # TODO: url
        with grpc.insecure_channel("localhost:1337") as channel:
            stub = MPCStub(channel)
            for i in range(MAX_ATTEMPTS):
                response = stub.GetTask(TaskRequest(task_id=task_id))
                if response.state not in [Task.TaskState.CREATED, Task.TaskState.RUNNING]:
                    return response
                time.sleep(ATTEMPT_DELAY_S)
        return None
        



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

    def verify_pin(self, pin) -> bool:
        return True
        self.attempts_left -= 1

        # FIXME: do we care about constant time comparison?
        result = pin == self.pin

        if result:
            self.attempts_left += 1

        return result

    def is_validated(self) -> bool:
        return True

    def reset():
        pass


class InstructionType(Enum):
    """ 
    Holds instruction constants
    """
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
    INS_GET_RESPONSE = 0xC0
    INS_SET_PIN = 0x22


class PinType(Enum):
    AUTH_PIN_REFERENCE = 0x01
    SING_PIN_REFERENCE = 0x02
    ADMIN_PIN_REFERENCE = 0x03

class Reference(Enum):
    AUTH_KEYPAIR_REFERENCE = 0x01
    SIGNING_KEYPAIR_REFERENCE = 0x02
    KEYPAIR_GENERATION_REFERENCE = 0x08
    GET_PUBLIC_KEY_REFERENCE = 0x09

class CustomSW(Enum):
    SW_PIN_VERIFICATION_REQUIRED = 0x6301


def format_unsigned_short(num):
    """
    Serializes an unsigned short using small endian
    """
    return struct.pack(">H", num)
