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

#ifndef SERVICES_INCLUDE_INPUT_METHOD_PROPERTY_H
#define SERVICES_INCLUDE_INPUT_METHOD_PROPERTY_H

namespace OHOS {
namespace MiscServices {
struct InputMethodInfo {
    std::string mImeId;
    std::string mPackageName;
    std::string mAbilityName;
    std::string mConfigurationPage;
    bool isSystemIme = false;
    int32_t mDefaultImeId = 0;
    uint32_t labelId = 0;
    uint32_t descriptionId = 0;
    std::string label;
    std::string description;
};
} // namespace MiscServices
} // namespace OHOS
#endif // SERVICES_INCLUDE_INPUT_METHOD_PROPERTY_H
