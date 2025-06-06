/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef INPUTMETHOD_IMF_INPUT_METHOD_STATUS_H
#define INPUTMETHOD_IMF_INPUT_METHOD_STATUS_H

#include "message_parcel.h"

namespace OHOS ::MiscServices {
enum InputMethodStatus : uint32_t {
    DISABLE = 0,
    ENABLE,
    ALL
};

enum class EnabledStatus : int32_t {
    DISABLED = 0,
    BASIC_MODE,
    FULL_EXPERIENCE_MODE,
};
} // namespace OHOS::MiscServices
#endif // namespace OHOS::INPUTMETHOD_IMF_INPUT_METHOD_STATUS_H
