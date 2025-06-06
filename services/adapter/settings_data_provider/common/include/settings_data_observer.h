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

#ifndef SETTINGS_DATA_OBSERVER_H
#define SETTINGS_DATA_OBSERVER_H

#include <cstdint>

#include "data_ability_observer_stub.h"

namespace OHOS {
namespace MiscServices {
class SettingsDataObserver : public AAFwk::DataAbilityObserverStub {
public:
    using CallbackFunc = std::function<void()>;
    SettingsDataObserver(const std::string &uriProxy, const std::string &key, const CallbackFunc &func)
        : uriProxy_(uriProxy), key_(key), func_(func){};
    ~SettingsDataObserver() = default;
    void OnChange() override;
    const std::string &GetUriProxy();
    const std::string &GetKey();

private:
    std::string uriProxy_;
    std::string key_;
    CallbackFunc func_ = nullptr;
};
} // namespace MiscServices
} // namespace OHOS

#endif // SETTINGS_DATA_OBSERVER_H
