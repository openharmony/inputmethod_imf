/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef CJ_INPUTMETHOD_EXTENSION_OBJECT_H
#define CJ_INPUTMETHOD_EXTENSION_OBJECT_H

#include "cj_common_ffi.h"
#include "configuration.h"
#include "want.h"

namespace OHOS {
namespace AbilityRuntime {
using InputMethodExtesionAbilityHandle = void *;
using WantHandle = void *;

/**
 * @brief cj InputMethodExtension object.
 */
class CjInputMethodExtensionObject {
public:
    CjInputMethodExtensionObject() : cjId_(0) { }
    ~CjInputMethodExtensionObject() = default;

    int32_t Init(const std::string &abilityName, InputMethodExtesionAbilityHandle handle);
    void OnCreate(const AAFwk::Want &want);
    void OnDestroy();
    void Destroy();

protected:
    int64_t cjId_;
};
} // namespace AbilityRuntime
} // namespace OHOS

#endif // CJ_INPUTMETHOD_EXTENSION_OBJECT_H
