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

#include "keyevent_consumer_service_impl.h"

#include "global.h"

namespace OHOS {
namespace MiscServices {
KeyEventConsumerServiceImpl::KeyEventConsumerServiceImpl(KeyEventCallback callback,
    std::shared_ptr<MMI::KeyEvent> keyEvent) : callback_(callback), keyEvent_(keyEvent) {}

KeyEventConsumerServiceImpl::~KeyEventConsumerServiceImpl() {}

ErrCode KeyEventConsumerServiceImpl::OnKeyEventResult(bool isConsumed)
{
    if (callback_ != nullptr) {
        callback_(keyEvent_, isConsumed);
    } else {
        IMSA_HILOGE("callback is nullptr, isConsumed: %{public}d!", isConsumed);
    }
    return ERR_OK;
}
} // namespace MiscServices
} // namespace OHOS