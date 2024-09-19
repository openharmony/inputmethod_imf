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

#include "ime_info_inquirer.h"

namespace OHOS {
namespace MiscServices {
std::shared_ptr<ImeInfo> ImeInfoInquirer::defaultIme_ = nullptr;
std::shared_ptr<Property> ImeInfoInquirer::defaultImeProperty_ = nullptr;
std::shared_ptr<Property> ImeInfoInquirer::currentIme_ = nullptr;
constexpr const char *MOCK_APP_ID = "MockAppId";
ImeInfoInquirer &ImeInfoInquirer::GetInstance()
{
    static ImeInfoInquirer instance;
    return instance;
}

std::shared_ptr<ImeInfo> ImeInfoInquirer::GetDefaultImeInfo(int32_t userId)
{
    return defaultIme_;
}

std::shared_ptr<Property> ImeInfoInquirer::GetCurrentInputMethod(int32_t userId)
{
    return currentIme_;
}

std::shared_ptr<Property> ImeInfoInquirer::GetDefaultImeCfgProp()
{
    return defaultImeProperty_;
}

bool ImeInfoInquirer::GetImeAppId(int32_t userId, const std::string &bundleName, std::string &appId)
{
    appId = MOCK_APP_ID;
    return true;
}

bool ImeInfoInquirer::GetImeVersionCode(int32_t userId, const std::string &bundleName, uint32_t &versionCode)
{
    versionCode = 0;
    return true;
}
} // namespace MiscServices
} // namespace OHOS