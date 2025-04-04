/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_STUB_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_STUB_H

#include <cstdint>

#include "i_input_client.h"
#include "ime_event_monitor_manager.h"
#include "iremote_stub.h"
#include "inputmethod_message_handler.h"
#include "message_option.h"
#include "message_parcel.h"
#include "nocopyable.h"
#include "refbase.h"

namespace OHOS {
namespace MiscServices {
class InputClientStub : public IRemoteStub<IInputClient> {
public:
    DISALLOW_COPY_AND_MOVE(InputClientStub);
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    InputClientStub();
    ~InputClientStub();

    int32_t OnInputReady(
        const sptr<IRemoteObject> &agent, const std::pair<int64_t, std::string> &imeInfo = {}) override;
    int32_t OnInputStop(bool isStopInactiveClient, bool isAsync = false) override;
    int32_t OnSwitchInput(const Property &property, const SubProperty &subProperty) override;
    int32_t OnPanelStatusChange(const InputWindowStatus &status, const ImeWindowInfo &info) override;
    int32_t NotifyInputStart(uint32_t callingWndId, int32_t requestKeyboardReason) override;
    int32_t NotifyInputStop() override;
    void DeactivateClient() override;

private:
    void OnInputReadyOnRemote(MessageParcel &data, MessageParcel &reply);
    int32_t OnInputStopOnRemote(MessageParcel &data, MessageParcel &reply);
    int32_t OnSwitchInputOnRemote(MessageParcel &data, MessageParcel &reply);
    int32_t OnPanelStatusChangeOnRemote(MessageParcel &data, MessageParcel &reply);
    int32_t DeactivateClientOnRemote(MessageParcel &data, MessageParcel &reply);
    int32_t NotifyInputStartOnRemote(MessageParcel &data, MessageParcel &reply);
    int32_t NotifyInputStopOnRemote(MessageParcel &data, MessageParcel &reply);
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_CLIENT_STUB_H
