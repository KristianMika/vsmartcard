from __future__ import annotations  # Enable return class annotations
from typing import Optional, Tuple, Type
import grpc
from enum import Enum
import struct
from datetime import datetime
import time
from threading import Thread, Event
import logging
from smartcard.System import readers


from virtualsmartcard.SmartcardFilesystem import MF
from virtualsmartcard.SEutils import Security_Environment
from virtualsmartcard.SmartcardSAM import SAM
from virtualsmartcard.VirtualSmartcard import Iso7816OS
from virtualsmartcard.SWutils import SwError, SW
from virtualsmartcard.cards.mpc_pb2 import SignRequest, TaskRequest, Task
from virtualsmartcard.cards.mpc_pb2_grpc import MPCStub
from virtualsmartcard.ConstantDefinitions import MAX_SHORT_LE

ApduResponse: Type = Tuple[int, bytes]


class MeesignOS(Iso7816OS):
    """
    This class implements a meesign virtual card that is used for Nextcloud authentication.
    The virtual card provides an interface between a meesign server and a webeid application.
    """

    INFINIT_EID_ATR = bytes([0x3b,
                             0xd5,
                             0x18,
                             0xff,
                             0x81,
                             0x91,
                             0xfe,
                             0x1f,
                             0xc3,
                             0x80,
                             0x73,
                             0xc8,
                             0x21,
                             0x10,
                             0x0a])
    SELF_PING_TIMER_SECONDS = 30

    def __init__(self, mf, sam, _meesign_url, _group_id,
                 meesign_ca_cert_path, ins2handler=None, maxle=MAX_SHORT_LE):
        Iso7816OS.__init__(self, mf, sam, ins2handler, maxle)
        self.ins2handler = {
            0x01: self.SAM.generate_keypair,
            0x02: self.SAM.get_public_key,
            0x03: self.SAM.store_certificate,
            0x04: self.SAM.get_certificate,
            0x20: self.SAM.verify,
            0x22: self.SAM.manage_security_environment,
            0x26: self.SAM.retries_left,
            0x2A: self.SAM.perform_security_operation,
            0x88: self.SAM.authenticate,
            0xa4: self.mf.selectFile,
            0xb0: self.mf.readBinaryPlain,  # TODO improve
            0xc0: self.getResponse
        }
        self.atr = MeesignOS.INFINIT_EID_ATR

        sam.meesign_url = _meesign_url
        if not _group_id:
            raise ValueError("group_id not specified")
        group_id = bytes.fromhex(_group_id)
        sam.group_id = group_id
        sam.auth_pubkey = group_id
        mf.auth_cert = []
        sam.set_ssl_credentials(meesign_ca_cert_path)

        self_ping = RepeatingTimer(
            MeesignOS.SELF_PING_TIMER_SECONDS, pingThisCard)
        # comment the line bellow to disable self-ping
        self_ping.start()


class MeesignSE(Security_Environment):
    pass


class MeesignMF(MF):

    AID = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])

    def selectFile(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        if data == MeesignMF.AID:
            return SW["NORMAL"], b""
        # self.append(TransparentStructureEF(parent=self, fid=FileType.FID_3F00.value,
            #    shortfid=0x1c, data=self.auth_cert))

        # return MF.selectFile(self, p1:int, p2:int, data:bytes)

        # TODO: use the ducking filesystem implementation
        # if p1 == 0x00:
        self.selected_file = FileType.FID_3F00
        # else:
        # return SW["ERR_FILENOTFOUND"], b""
        # self.selected_file = FileType.FID_DDCE #TODO: completely wrong

        return SW["NORMAL"], b""

    def readBinaryPlain(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        file = None
        offset = get_short(bytes([p1, p2]))

        if self.selected_file == FileType.FID_3F00:
            file = self.auth_cert[offset:]
        elif self.selected_file == FileType.FID_DDCE:
            return SW["ERR_FILENOTFOUND"], b""
        else:
            return SW["ERR_FILENOTFOUND"], b""

        return SW["NORMAL"], file


class MeesignSAM(SAM):
    def __init__(self, mf=None):
        SAM.__init__(self, None, None, mf, default_se=MeesignSE)
        self.current_SE = self.default_se(self.mf, self)
        self.pins = {
            PinType.ADMIN_PIN_REFERENCE: Pin(),
            PinType.AUTH_PIN_REFERENCE: Pin(),
            PinType.SING_PIN_REFERENCE: Pin()
        }

    def generate_keypair(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        """
        We are not generating any keys here, just return the success SW
        """
        if not self.pins.get(PinType.ADMIN_PIN_REFERENCE).is_validated():
            # TODO: SW_PIN_VERIFICATION_REQUIRED
            raise SwError(SW["ERR_SECSTATUS"])
        return SW["NORMAL"], b""

    def get_public_key(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        key = None
        if p1 == Reference.AUTH_KEYPAIR_REFERENCE.value:
            key = self.auth_pubkey  # TODO: store keys in a struct
        elif p1 == Reference.SIGNING_KEYPAIR_REFERENCE.value:
            key = self.auth_pubkey  # TODO: wrong

            raise SwError(SW["ERR_NOTSUPPORTED"])

            # key = self.signing_pubkey
            # TODO: implement signing?
        else:
            # TODO: not in the original applet
            raise SwError(SW["ERR_INCORRECTP1P2"])

        if p2 != Reference.GET_PUBLIC_KEY_REFERENCE.value:
            raise SwError(SW["ERR_INCORRECTP1P2"])
        return SW["NORMAL"], key

    def store_certificate(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        if not self.pins.get(PinType.ADMIN_PIN_REFERENCE).is_validated():
            raise SwError(CustomSW.SW_PIN_VERIFICATION_REQUIRED)

        if p1 == 0x01:
            assert (self.mf.auth_cert != data)
            self.mf.auth_cert += data

        elif p1 == 0x02:
            raise SwError(SW["ERR_NOTSUPPORTED"])

            self.mf.signing_cert += data
        else:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        self.pins.get(PinType.ADMIN_PIN_REFERENCE).reset()
        return SW["NORMAL"], b""

    def get_certificate(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        if p1 == 0x01:
            return SW["NORMAL"], self.mf.auth_cert
        elif p1 == 0x02:
            raise SwError(SW["ERR_NOTSUPPORTED"])

            # TODO: implement signing?
            return SW["NORMAL"], self.mf.signing_cert
        else:
            raise SwError(SW["ERR_INCORRECTP1P2"])

    def authenticate(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        """
        Authenticate function is used for login authentication
        """
        if not self.pins.get(PinType.AUTH_PIN_REFERENCE).is_validated():
            raise SwError(CustomSW.SW_PIN_VERIFICATION_REQUIRED)

        curr_datetime = datetime.now().strftime('%d.%m.%Y, %H:%M:%S')
        task_id = self.__create_task(
            f"Nextcloud authentication request from {curr_datetime}",
            self.group_id,
            data)
        task = self.__wait_for_task(task_id)
        if task is None or task.state == Task.TaskState.FAILED:
            raise SwError(SW["ERR_NOINFO6A"])  # TODO: better error

        self.pins.get(PinType.AUTH_PIN_REFERENCE).reset()
        return SW["NORMAL"], task.data

    def __create_task(self, name: str, group_id: bytes, data: bytes) -> bytes:
        """
        Creates a new signing task

        :param name: Name of the task
        :param group_id: Id of the signing group
        :param data: Data containing the signing challenge to be signed
        :returns: ID of the created task
        """
        with grpc.secure_channel(self.meesign_url, self.ssl_credentials) as channel:
            stub = MPCStub(channel)
            response = stub.Sign(SignRequest(
                name=name, group_id=group_id, data=data))
        logging.debug(f"Task id: {response.id.hex()}")
        return response.id

    def __wait_for_task(self, task_id: bytes) -> Optional[Task]:
        """
        Busy-waits for a task with the specified `task_id` to be finished
        :param task_id: id of the task to wait for
        :returns: task if it successfully finished, None otherwise
        """
        MAX_ATTEMPTS = 60
        ATTEMPT_DELAY_S = 1

        with grpc.secure_channel(self.meesign_url, self.ssl_credentials) as channel:
            stub = MPCStub(channel)
            for _ in range(MAX_ATTEMPTS):
                logging.debug("Waiting for task...")
                response = stub.GetTask(TaskRequest(task_id=task_id))
                if response.state not in [
                        Task.TaskState.CREATED, Task.TaskState.RUNNING]:
                    return response
                time.sleep(ATTEMPT_DELAY_S)
        return None

    def set_ssl_credentials(self, meesign_ca_cert_path):
        """
        Reads the cert of meesign CA and instantiates SSL credentials
        used for communication with meesign server
        """
        if not meesign_ca_cert_path:
            raise ValueError("Meesign CA certificate path not supplied")

        with open(meesign_ca_cert_path, 'rb') as f:
            cert = f.read()
        self.ssl_credentials = grpc.ssl_channel_credentials(cert)

    def manage_security_environment(
            self, p1: int, p2: int, data: bytes) -> ApduResponse:
        """
        Sets the specified pin
        """
        if p1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        pin = self.__get_pin(p2)

        admin_pin = self.pins.get(PinType.ADMIN_PIN_REFERENCE)
        if admin_pin.is_set() and not admin_pin.is_validated():
            raise SwError(SW["ERR_SECSTATUS"])
        pin.set_pin(data)
        # pin.resetAndUnblock(); TODO
        admin_pin.reset()
        if not admin_pin.is_set() and p2 == PinType.ADMIN_PIN_REFERENCE.value:
            admin_pin._is_set = True
        return SW["NORMAL"], b""

    def verify(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        """
        Verifies the suplied PIN
        """
        return SW["NORMAL"], b""
        if p1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        if len(data) > Pin.PIN_MAX_SIZE:
            raise SwError(SW["SW_WRONG_LENGTH"])

        req_pin = self.__get_pin(p2)

        if req_pin.attempts_left() == 0:
            raise SwError(SW["SW_PIN_BLOCKED"])

        if not req_pin.verify_pin(data):
            raise SwError(SW["SW_WRONG_PIN_X_TRIES_LEFT"])

        return SW["NORMAL"], b""

    def retries_left(self, p1: int, p2: int, data: bytes) -> ApduResponse:
        """
        Returns the number of verification attempts left for the requested PIN
        """
        if p1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        req_pin = self.__get_pin(p2)
        # TODO: for whatever reason the lower solution does not work
        return SW["NORMAL"], bytes([0x03, 0x03])

        return SW["NORMAL"], format_unsigned_short(req_pin.attempts_left())

    def __get_pin(self, pin_type: int) -> Pin:
        pintype = PinType(pin_type)
        if not pintype:
            raise SwError(SW["ERR_INCORRECTP1P2"])
        return self.pins.get(pintype)

    def perform_security_operation(
            self, p1: int, p2: int, data: bytes) -> ApduResponse:
        """
        We don't currently support signing, only authentication
        """
        raise SwError(SW["ERR_NOTSUPPORTED"])


class Pin:
    """
    Represents a PIN instance
    # TODO: WIP, every verification returns True
    """

    PIN_MAX_SIZE = 12
    DEFAULT_ATEMPT_COUNT = 3

    def __init__(self):
        self.attempts = Pin.DEFAULT_ATEMPT_COUNT
        self._is_set = False

    def set_pin(self, new_pin: bytes):
        self._is_set = True
        self.pin = new_pin

    def change_pin(self, new_pin: bytes):
        self.pin = new_pin

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

    def reset(self):
        pass

    def is_set(self) -> bool:
        return True
        return self._is_set


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


class FileType(Enum):
    FID_3F00 = 0x3F00
    FID_AACE = 0xAACE
    FID_DDCE = 0xDDCE


def format_unsigned_short(num):
    """
    Serializes an unsigned short using small endian
    """
    return struct.pack(">H", num)


def get_short(nums):
    """
    Returns a small-endian short decoded from bytes
    """
    return struct.unpack(">H", nums)[0]


class RepeatingTimer(Thread):
    def __init__(self, interval_seconds, callback):
        super().__init__()
        self.stop_event = Event()
        self.interval_seconds = interval_seconds
        self.callback = callback

    def run(self):
        while not self.stop_event.wait(self.interval_seconds):
            self.callback()

    def stop(self):
        self.stop_event.set()


def pingThisCard():
    logging.info(f"About to self-ping...")
    reader = readers()[0]
    conn = reader.createConnection()
    conn.connect()
    response, sw1, sw2 = conn.transmit(
        [0x00, 0xA4, 0x04, 0x00, 0x08, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
