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

#include <mutex>
#include <thread>
#include <vector>

#ifndef INPUTMETHOD_IMF_INPUT_METHOD_PROPERTY_H
#define INPUTMETHOD_IMF_INPUT_METHOD_PROPERTY_H

namespace OHOS {
namespace MiscServices {
struct Property {
    std::string name;     // the bundleName of inputMethod
    std::string id;       // the extensionName of inputMethod
    std::string label;    // the label of inputMethod
    uint32_t labelId = 0; // the labelId of inputMethod
    std::string icon;     // the icon of inputMethod
    uint32_t iconId = 0;  // the icon id of inputMethod
};

struct SubProperty {
    std::string label;    // the label of subtype
    uint32_t labelId = 0; // the labelId of subtype
    std::string name;     // the bundleName of inputMethod
    std::string id;       // the name of subtype
    std::string mode;     // the mode of subtype, containing "upper" and "lower"
    std::string locale;   // the tongues of subtype, such as "zh_CN", "en_US", etc.
    std::string language; // the language of subtype
    std::string icon;     // the icon of subtype
    uint32_t iconId = 0;  // the icon id of subtype
};

struct FullImeInfo {
    bool isNewIme { false };
    uint32_t tokenId { 0 };
    std::string appId;
    uint32_t versionCode;
    Property prop;
    std::vector<SubProperty> subProps;
};

struct ImeInfo : public FullImeInfo {
    SubProperty subProp;
    bool isSpecificSubName { true };
};
} // namespace MiscServices
} // namespace OHOS

#endif // INPUTMETHOD_IMF_INPUT_METHOD_PROPERTY_H
