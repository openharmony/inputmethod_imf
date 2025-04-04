/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "system_cmd_channel_stub.h"

#include "global.h"
#include "ime_system_channel.h"
#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "itypes_util.h"
#include "message.h"

namespace OHOS {
namespace MiscServices {
SystemCmdChannelStub::SystemCmdChannelStub() { }

SystemCmdChannelStub::~SystemCmdChannelStub() { }

int32_t SystemCmdChannelStub::SendPrivateCommand(
    const std::unordered_map<std::string, PrivateDataValue> &privateCommand)
{
    return ImeSystemCmdChannel::GetInstance()->ReceivePrivateCommand(privateCommand);
}

int32_t SystemCmdChannelStub::SendPrivateCommandOnRemote(MessageParcel &data, MessageParcel &reply)
{
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    if (!ITypesUtil::Unmarshal(data, privateCommand)) {
        IMSA_HILOGE("failed to read message parcel!");
        return ErrorCode::ERROR_EX_PARCELABLE;
    }
    return reply.WriteInt32(SendPrivateCommand(privateCommand)) ? ErrorCode::NO_ERROR : ErrorCode::ERROR_EX_PARCELABLE;
}

int32_t SystemCmdChannelStub::NotifyPanelStatus(const SysPanelStatus &sysPanelStatus)
{
    return ImeSystemCmdChannel::GetInstance()->NotifyPanelStatus(sysPanelStatus);
}

int32_t SystemCmdChannelStub::NotifyPanelStatusOnRemote(MessageParcel &data, MessageParcel &reply)
{
    SysPanelStatus sysPanelStatus;
    if (!ITypesUtil::Unmarshal(data, sysPanelStatus)) {
        IMSA_HILOGE("failed to read message parcel!");
        return ErrorCode::ERROR_EX_PARCELABLE;
    }
    return reply.WriteInt32(NotifyPanelStatus(sysPanelStatus)) ? ErrorCode::NO_ERROR : ErrorCode::ERROR_EX_PARCELABLE;
}

int32_t SystemCmdChannelStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    IMSA_HILOGI("SystemCmdChannelStub, code: %{public}u, callingPid: %{public}d, callingUid: %{public}d.", code,
        IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid());
    auto descriptorToken = data.ReadInterfaceToken();
    if (descriptorToken != ISystemCmdChannel::GetDescriptor()) {
        IMSA_HILOGE("SystemCmdChannelStub descriptor error!");
        return ErrorCode::ERROR_STATUS_UNKNOWN_TRANSACTION;
    }
    if (code < SYSTEM_CMD_BEGIN || code >= SYSTEM_CMD_END) {
        IMSA_HILOGE("code error, code = %{public}u, callingPid: %{public}d, callingUid: %{public}d.", code,
            IPCSkeleton::GetCallingPid(), IPCSkeleton::GetCallingUid());
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    return (this->*HANDLERS[code])(data, reply);
}
} // namespace MiscServices
} // namespace OHOS