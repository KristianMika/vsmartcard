# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

import meesign_pb2 as meesign__pb2

GRPC_GENERATED_VERSION = '1.64.0'
GRPC_VERSION = grpc.__version__
EXPECTED_ERROR_RELEASE = '1.65.0'
SCHEDULED_RELEASE_DATE = 'June 25, 2024'
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    warnings.warn(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in meesign_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
        + f' This warning will become an error in {EXPECTED_ERROR_RELEASE},'
        + f' scheduled for release on {SCHEDULED_RELEASE_DATE}.',
        RuntimeWarning
    )


class MeeSignStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.GetServerInfo = channel.unary_unary(
                '/meesign.MeeSign/GetServerInfo',
                request_serializer=meesign__pb2.ServerInfoRequest.SerializeToString,
                response_deserializer=meesign__pb2.ServerInfo.FromString,
                _registered_method=True)
        self.Register = channel.unary_unary(
                '/meesign.MeeSign/Register',
                request_serializer=meesign__pb2.RegistrationRequest.SerializeToString,
                response_deserializer=meesign__pb2.RegistrationResponse.FromString,
                _registered_method=True)
        self.Sign = channel.unary_unary(
                '/meesign.MeeSign/Sign',
                request_serializer=meesign__pb2.SignRequest.SerializeToString,
                response_deserializer=meesign__pb2.Task.FromString,
                _registered_method=True)
        self.Group = channel.unary_unary(
                '/meesign.MeeSign/Group',
                request_serializer=meesign__pb2.GroupRequest.SerializeToString,
                response_deserializer=meesign__pb2.Task.FromString,
                _registered_method=True)
        self.Decrypt = channel.unary_unary(
                '/meesign.MeeSign/Decrypt',
                request_serializer=meesign__pb2.DecryptRequest.SerializeToString,
                response_deserializer=meesign__pb2.Task.FromString,
                _registered_method=True)
        self.GetTask = channel.unary_unary(
                '/meesign.MeeSign/GetTask',
                request_serializer=meesign__pb2.TaskRequest.SerializeToString,
                response_deserializer=meesign__pb2.Task.FromString,
                _registered_method=True)
        self.UpdateTask = channel.unary_unary(
                '/meesign.MeeSign/UpdateTask',
                request_serializer=meesign__pb2.TaskUpdate.SerializeToString,
                response_deserializer=meesign__pb2.Resp.FromString,
                _registered_method=True)
        self.DecideTask = channel.unary_unary(
                '/meesign.MeeSign/DecideTask',
                request_serializer=meesign__pb2.TaskDecision.SerializeToString,
                response_deserializer=meesign__pb2.Resp.FromString,
                _registered_method=True)
        self.AcknowledgeTask = channel.unary_unary(
                '/meesign.MeeSign/AcknowledgeTask',
                request_serializer=meesign__pb2.TaskAcknowledgement.SerializeToString,
                response_deserializer=meesign__pb2.Resp.FromString,
                _registered_method=True)
        self.GetTasks = channel.unary_unary(
                '/meesign.MeeSign/GetTasks',
                request_serializer=meesign__pb2.TasksRequest.SerializeToString,
                response_deserializer=meesign__pb2.Tasks.FromString,
                _registered_method=True)
        self.GetGroups = channel.unary_unary(
                '/meesign.MeeSign/GetGroups',
                request_serializer=meesign__pb2.GroupsRequest.SerializeToString,
                response_deserializer=meesign__pb2.Groups.FromString,
                _registered_method=True)
        self.GetDevices = channel.unary_unary(
                '/meesign.MeeSign/GetDevices',
                request_serializer=meesign__pb2.DevicesRequest.SerializeToString,
                response_deserializer=meesign__pb2.Devices.FromString,
                _registered_method=True)
        self.Log = channel.unary_unary(
                '/meesign.MeeSign/Log',
                request_serializer=meesign__pb2.LogRequest.SerializeToString,
                response_deserializer=meesign__pb2.Resp.FromString,
                _registered_method=True)
        self.SubscribeUpdates = channel.unary_stream(
                '/meesign.MeeSign/SubscribeUpdates',
                request_serializer=meesign__pb2.SubscribeRequest.SerializeToString,
                response_deserializer=meesign__pb2.Task.FromString,
                _registered_method=True)


class MeeSignServicer(object):
    """Missing associated documentation comment in .proto file."""

    def GetServerInfo(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Register(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Sign(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Group(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Decrypt(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetTask(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def UpdateTask(self, request, context):
        """auth required
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def DecideTask(self, request, context):
        """auth required
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def AcknowledgeTask(self, request, context):
        """auth required
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetTasks(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetGroups(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetDevices(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def Log(self, request, context):
        """auth optional
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SubscribeUpdates(self, request, context):
        """auth required
        """
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_MeeSignServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'GetServerInfo': grpc.unary_unary_rpc_method_handler(
                    servicer.GetServerInfo,
                    request_deserializer=meesign__pb2.ServerInfoRequest.FromString,
                    response_serializer=meesign__pb2.ServerInfo.SerializeToString,
            ),
            'Register': grpc.unary_unary_rpc_method_handler(
                    servicer.Register,
                    request_deserializer=meesign__pb2.RegistrationRequest.FromString,
                    response_serializer=meesign__pb2.RegistrationResponse.SerializeToString,
            ),
            'Sign': grpc.unary_unary_rpc_method_handler(
                    servicer.Sign,
                    request_deserializer=meesign__pb2.SignRequest.FromString,
                    response_serializer=meesign__pb2.Task.SerializeToString,
            ),
            'Group': grpc.unary_unary_rpc_method_handler(
                    servicer.Group,
                    request_deserializer=meesign__pb2.GroupRequest.FromString,
                    response_serializer=meesign__pb2.Task.SerializeToString,
            ),
            'Decrypt': grpc.unary_unary_rpc_method_handler(
                    servicer.Decrypt,
                    request_deserializer=meesign__pb2.DecryptRequest.FromString,
                    response_serializer=meesign__pb2.Task.SerializeToString,
            ),
            'GetTask': grpc.unary_unary_rpc_method_handler(
                    servicer.GetTask,
                    request_deserializer=meesign__pb2.TaskRequest.FromString,
                    response_serializer=meesign__pb2.Task.SerializeToString,
            ),
            'UpdateTask': grpc.unary_unary_rpc_method_handler(
                    servicer.UpdateTask,
                    request_deserializer=meesign__pb2.TaskUpdate.FromString,
                    response_serializer=meesign__pb2.Resp.SerializeToString,
            ),
            'DecideTask': grpc.unary_unary_rpc_method_handler(
                    servicer.DecideTask,
                    request_deserializer=meesign__pb2.TaskDecision.FromString,
                    response_serializer=meesign__pb2.Resp.SerializeToString,
            ),
            'AcknowledgeTask': grpc.unary_unary_rpc_method_handler(
                    servicer.AcknowledgeTask,
                    request_deserializer=meesign__pb2.TaskAcknowledgement.FromString,
                    response_serializer=meesign__pb2.Resp.SerializeToString,
            ),
            'GetTasks': grpc.unary_unary_rpc_method_handler(
                    servicer.GetTasks,
                    request_deserializer=meesign__pb2.TasksRequest.FromString,
                    response_serializer=meesign__pb2.Tasks.SerializeToString,
            ),
            'GetGroups': grpc.unary_unary_rpc_method_handler(
                    servicer.GetGroups,
                    request_deserializer=meesign__pb2.GroupsRequest.FromString,
                    response_serializer=meesign__pb2.Groups.SerializeToString,
            ),
            'GetDevices': grpc.unary_unary_rpc_method_handler(
                    servicer.GetDevices,
                    request_deserializer=meesign__pb2.DevicesRequest.FromString,
                    response_serializer=meesign__pb2.Devices.SerializeToString,
            ),
            'Log': grpc.unary_unary_rpc_method_handler(
                    servicer.Log,
                    request_deserializer=meesign__pb2.LogRequest.FromString,
                    response_serializer=meesign__pb2.Resp.SerializeToString,
            ),
            'SubscribeUpdates': grpc.unary_stream_rpc_method_handler(
                    servicer.SubscribeUpdates,
                    request_deserializer=meesign__pb2.SubscribeRequest.FromString,
                    response_serializer=meesign__pb2.Task.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'meesign.MeeSign', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('meesign.MeeSign', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class MeeSign(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def GetServerInfo(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/GetServerInfo',
            meesign__pb2.ServerInfoRequest.SerializeToString,
            meesign__pb2.ServerInfo.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Register(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/Register',
            meesign__pb2.RegistrationRequest.SerializeToString,
            meesign__pb2.RegistrationResponse.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Sign(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/Sign',
            meesign__pb2.SignRequest.SerializeToString,
            meesign__pb2.Task.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Group(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/Group',
            meesign__pb2.GroupRequest.SerializeToString,
            meesign__pb2.Task.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Decrypt(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/Decrypt',
            meesign__pb2.DecryptRequest.SerializeToString,
            meesign__pb2.Task.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetTask(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/GetTask',
            meesign__pb2.TaskRequest.SerializeToString,
            meesign__pb2.Task.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def UpdateTask(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/UpdateTask',
            meesign__pb2.TaskUpdate.SerializeToString,
            meesign__pb2.Resp.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def DecideTask(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/DecideTask',
            meesign__pb2.TaskDecision.SerializeToString,
            meesign__pb2.Resp.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def AcknowledgeTask(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/AcknowledgeTask',
            meesign__pb2.TaskAcknowledgement.SerializeToString,
            meesign__pb2.Resp.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetTasks(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/GetTasks',
            meesign__pb2.TasksRequest.SerializeToString,
            meesign__pb2.Tasks.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetGroups(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/GetGroups',
            meesign__pb2.GroupsRequest.SerializeToString,
            meesign__pb2.Groups.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetDevices(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/GetDevices',
            meesign__pb2.DevicesRequest.SerializeToString,
            meesign__pb2.Devices.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def Log(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/meesign.MeeSign/Log',
            meesign__pb2.LogRequest.SerializeToString,
            meesign__pb2.Resp.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def SubscribeUpdates(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_stream(
            request,
            target,
            '/meesign.MeeSign/SubscribeUpdates',
            meesign__pb2.SubscribeRequest.SerializeToString,
            meesign__pb2.Task.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
