/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_LISTEN_EVENT_MANAGER_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_LISTEN_EVENT_MANAGER_H

#include "ime_event_listener.h"

namespace OHOS {
namespace MiscServices {
class EventStatusManager {
public:
    inline static bool IsImeShowOn(uint32_t eventFlag)
    {
        return (eventFlag & EVENT_IME_SHOW_MASK) == EVENT_IME_SHOW_MASK;
    }
    inline static bool IsImeChangeOn(uint32_t eventFlag)
    {
        return (eventFlag & EVENT_IME_CHANGE_MASK) == EVENT_IME_CHANGE_MASK;
    }
    inline static bool IsImeHideOn(uint32_t eventFlag)
    {
        return (eventFlag & EVENT_IME_HIDE_MASK) == EVENT_IME_HIDE_MASK;
    }
    inline static bool IsInputStatusChangedOn(uint32_t eventFlag)
    {
        return (eventFlag & EVENT_INPUT_STATUS_CHANGED_MASK) == EVENT_INPUT_STATUS_CHANGED_MASK;
    }
};
} // namespace MiscServices
} // namespace OHOS

#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_LISTEN_EVENT_MANAGER_H
