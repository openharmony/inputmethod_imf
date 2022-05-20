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

#ifndef FM_IMC_PROJECT_INPUTMETHODAGENTPROXY_H
#define FM_IMC_PROJECT_INPUTMETHODAGENTPROXY_H

#include "iremote_proxy.h"
#include "i_input_method_agent.h"

namespace OHOS {
namespace MiscServices {
    class InputMethodAgentProxy : public IRemoteProxy<IInputMethodAgent> {
    public:
        explicit InputMethodAgentProxy(const sptr<IRemoteObject> &object);
        ~InputMethodAgentProxy() = default;
        DISALLOW_COPY_AND_MOVE(InputMethodAgentProxy);

        bool DispatchKeyEvent(MessageParcel& data) override;
        void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) override;
        void OnSelectionChange(std::u16string text, int32_t oldBegin, int32_t oldEnd,
                               int32_t newBegin, int32_t newEnd) override;
        void SetCallingWindow(uint32_t windowId) override;
    private:
        static inline BrokerDelegator<InputMethodAgentProxy> delegator_;
    };
}
}
#endif // FM_IMC_PROJECT_INPUTMETHODAGENTPROXY_H
