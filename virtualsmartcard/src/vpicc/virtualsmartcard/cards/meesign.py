from multiprocessing.sharedctypes import Value
import ssl
import grpc
from enum import Enum
import struct
from datetime import datetime
import time
from Crypto.PublicKey import ECC

from virtualsmartcard.SmartcardFilesystem import MF
from virtualsmartcard.SEutils import Security_Environment
from virtualsmartcard.SmartcardSAM import SAM
from virtualsmartcard.VirtualSmartcard import Iso7816OS
from virtualsmartcard.SWutils import SwError, SW
from virtualsmartcard.cards.mpc_pb2 import SignRequest, TaskRequest, Task
from virtualsmartcard.cards.mpc_pb2_grpc import MPCStub
from virtualsmartcard.ConstantDefinitions import MAX_SHORT_LE


class MeesignOS(Iso7816OS):
    """
    This class implements a meesign virtual card that is used for Nextcloud authentication.
    The virtual card provides an interface between a meesign server and a webeid application.
    """

    INFINIT_EID_ATR = bytes([0x3b, 0xfe, 0x18, 0x00, 0x00, 0x80, 0x31, 0xfe, 0x45, 0x80, 0x31,
                             0x80, 0x66, 0x40, 0x90, 0xa5, 0x10, 0x2e, 0x10, 0x83, 0x01, 0x90, 0x00, 0xf2])

    def __init__(self, mf, sam, _meesign_url, _group_id,  ins2handler=None, maxle=MAX_SHORT_LE):
        if not _group_id:
            raise ValueError("group_id not specified")
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
            0xb0: self.mf.readBinaryPlain, # TODO improve
            0xc0: self.getResponse
        }
        self.atr = MeesignOS.INFINIT_EID_ATR

        sam.meesign_url = _meesign_url
        group_id = bytes.fromhex(_group_id)
        sam.group_id =  group_id
        sam.auth_pubkey = group_id
        mf.auth_cert = []



class MeesignSE(Security_Environment):
    pass


class MeesignMF(MF):

    AID = bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
        

    def selectFile(self, p1, p2, data):
        if data == MeesignMF.AID:
            return SW["NORMAL"], b""
        # self.append(TransparentStructureEF(parent=self, fid=FileType.FID_3F00.value,
                    #    shortfid=0x1c, data=self.auth_cert))

        # return MF.selectFile(self, p1, p2, data)


        # TODO: use the ducking filesystem implementation
        # if p1 == 0x00:
        self.selected_file = FileType.FID_3F00
        # else:
            # return SW["ERR_FILENOTFOUND"], b""
            # self.selected_file = FileType.FID_DDCE #TODO: completely wrong



        return SW["NORMAL"], b""
        


    def readBinaryPlain(self, p1, p2, data):
        file = None
        offset = format_short(bytes([p1, p2]))


        if self.selected_file == FileType.FID_3F00:
            file = self.auth_cert[offset:min(offset + 0x80,len(self.auth_cert) )]
        elif self.selected_file == FileType.FID_DDCE:
            return SW["ERR_FILENOTFOUND"], b""
            
        else:
            print("not found file:", self.selected_file)
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
        

    def verify(self, p1, p2, data):
        """
        Verifies the suplied PIN
        """
        if p1 != 0x00:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        if len(data) > Pin.PIN_MAX_SIZE:
            raise SwError(SW["SW_WRONG_LENGTH"])

        req_pin = self.__get_pin(p2)

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

        req_pin = self.__get_pin(p2)

        return SW["NORMAL"], format_unsigned_short(req_pin.attempts_left())

    def perform_security_operation(self, p1, p2, data):
        raise SwError(SW["ERR_NOTSUPPORTED"])

        parameters = (p1 << 8) | p2
        if parameters != 0x9E9A:
            raise SwError(SW["ERR_INCORRECTP1P2"])


    def get_certificate(self, p1, p2, data):
        if p1 == 0x01:
            return SW["NORMAL"], self.mf.auth_cert
        elif p1 == 0x02:
            raise SwError(SW["ERR_NOTSUPPORTED"])

            # TODO: implement signing?
            return SW["NORMAL"], self.mf.signing_cert
        else:
            raise SwError(SW["ERR_INCORRECTP1P2"])

    def store_certificate(self, p1, p2, data):
        if not self.pins.get(PinType.ADMIN_PIN_REFERENCE).is_validated():
            raise SwError(CustomSW.SW_PIN_VERIFICATION_REQUIRED)

        if p1 == 0x01:
            assert(self.mf.auth_cert != data)
            self.mf.auth_cert += data

        elif p1 == 0x02:
            raise SwError(SW["ERR_NOTSUPPORTED"])
            print("Storing signing cert")

            self.mf.signing_cert += data
        else:
            raise SwError(SW["ERR_INCORRECTP1P2"])

        self.pins.get(PinType.ADMIN_PIN_REFERENCE).reset()
        return SW["NORMAL"], b""

    def get_public_key(self, p1, p2, data):
        key = None
        if p1 == Reference.AUTH_KEYPAIR_REFERENCE.value:
            key = self.auth_pubkey #TODO: store keys in a struct
        elif p1 == Reference.SIGNING_KEYPAIR_REFERENCE.value:
            key = self.auth_pubkey #TODO: wrong

            raise SwError(SW["ERR_NOTSUPPORTED"])

            # key = self.signing_pubkey
            # TODO: implement signing?
        else:
            # TODO: not in the original applet
            print("weird p1")
            raise SwError(SW["ERR_INCORRECTP1P2"])


        if p2 != Reference.GET_PUBLIC_KEY_REFERENCE.value:
            print("p2 not 09")
            raise SwError(SW["ERR_INCORRECTP1P2"])
        return SW["NORMAL"], key

    def manage_security_environment(self, p1, p2, data):
        """ 
        Set Pin
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
        if not admin_pin.is_set() and p2 == PinType.ADMIN_PIN_REFERENCE:
            admin_pin._is_set = True
        return SW["NORMAL"], b""        

    def generate_keypair(self, p1, p2, data):
        if not self.pins.get(PinType.ADMIN_PIN_REFERENCE).is_validated():
            raise SwError(SW["ERR_SECSTATUS"]) # TODO: SW_PIN_VERIFICATION_REQUIRED
        # missing impl
        return SW["NORMAL"], b""        



    def authenticate(self, p1, p2, data):
        if not self.pins.get(PinType.AUTH_PIN_REFERENCE).is_validated():
            raise SwError(CustomSW.SW_PIN_VERIFICATION_REQUIRED)

        curr_datetime = datetime.now().strftime('%d.%m.%Y, %H:%M:%S')
        task_id = self.__create_task("Nextcloud authentication request from " + curr_datetime, self.group_id, data)
        task = self.__wait_for_task(task_id)
        if task is None or task.state == Task.TaskState.FAILED:
            raise SwError(SW["ERR_NOINFO6A"]) #TODO: better error

        self.pins.get(PinType.AUTH_PIN_REFERENCE).reset()
        return SW["NORMAL"], task.data

    def __get_pin(self, pin_type: int):
        pintype = PinType(pin_type)
        if not pintype:
            raise SwError(SW["ERR_INCORRECTP1P2"])
        return self.pins.get(pintype)
        
    def __create_task(self, name: str, group_id: bytes, data: bytes):
        """
        Creates a new signing task

        :param name: Name of the task
        :param group_id: Id of the signing group
        :param data: Data containing the signing challenge to be signed    
        """
        # TODO: self.meesign_url fix
        # TODO: try grpc.secure_channel()

        with open('/home/kiko/Desktop/meesign-ca-cert.pem', 'rb') as f:
            cert = f.read()

        credentials = grpc.ssl_channel_credentials(cert)
        with grpc.secure_channel("meesign.local:1337",credentials) as channel:
            stub = MPCStub(channel)
            response = stub.Sign(SignRequest(
                name=name, group_id=group_id, data=data))
        print("Got response: ", response)
        return response.id

    def __wait_for_task(self, task_id: bytes):
        MAX_ATTEMPTS = 60
        ATTEMPT_DELAY_S = 1
        # TODO: url meesign.local by default
        with open('/home/kiko/Desktop/meesign-ca-cert.pem', 'rb') as f:
            cert = f.read()

        print("waiting... ")
        credentials = grpc.ssl_channel_credentials(cert)
        with grpc.secure_channel("meesign.local:1337", credentials) as channel:
            stub = MPCStub(channel)
            for _ in range(MAX_ATTEMPTS):
                print("waiting... ")
                response = stub.GetTask(TaskRequest(task_id=task_id))
                if response.state not in [Task.TaskState.CREATED, Task.TaskState.RUNNING]:
                    print(f"Got response: {response}")
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
        self._is_set = False

    def set_pin(self, new_pin: bytes):
        self._is_set = True
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

    def reset(self):
        pass

    def is_set(self):
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


def format_unsigned_short(num):
    """
    Serializes an unsigned short using small endian
    """
    return struct.pack(">H", num)

def format_short(nums):
    return struct.unpack(">H", nums)[0]

class FileType(Enum):
    FID_3F00 = 0x3F00
    FID_AACE = 0xAACE
    FID_DDCE = 0xDDCE