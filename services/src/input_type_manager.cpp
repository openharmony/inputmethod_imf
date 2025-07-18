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

#include "input_type_manager.h"


namespace OHOS {
namespace MiscServices {
InputTypeManager &InputTypeManager::GetInstance()
{
    static InputTypeManager instance;
    return instance;
}

bool InputTypeManager::IsSupported(InputType type)
{
    if (!isTypeCfgReady_.load() && !Init()) {
        IMSA_HILOGE("init cfg failed!");
        return false;
    }
    std::lock_guard<std::mutex> lock(typesLock_);
    return inputTypes_.find(type) != inputTypes_.end();
}

bool InputTypeManager::IsInputType(const ImeIdentification &ime)
{
    if (!isTypeCfgReady_.load() && !Init()) {
        IMSA_HILOGD("init cfg failed.");
        return false;
    }
    std::lock_guard<std::mutex> lock(listLock_);
    return inputTypeImeList_.find(ime) != inputTypeImeList_.end();
}

int32_t InputTypeManager::GetImeByInputType(InputType type, ImeIdentification &ime)
{
    if (!isTypeCfgReady_.load() && !Init()) {
        IMSA_HILOGE("init cfg failed!");
        return ErrorCode::ERROR_PARSE_CONFIG_FILE;
    }
    std::lock_guard<std::mutex> lock(typesLock_);
    auto iter = inputTypes_.find(type);
    if (iter == inputTypes_.end()) {
        IMSA_HILOGE("type: %{public}d not supported!", type);
        return ErrorCode::ERROR_IMSA_INPUT_TYPE_NOT_FOUND;
    }
    ime = iter->second;
    IMSA_HILOGI("type: %{public}d find ime: %{public}s|%{public}s.", type, ime.bundleName.c_str(), ime.subName.c_str());
    return ErrorCode::NO_ERROR;
}

void InputTypeManager::Set(bool isStarted, const ImeIdentification &currentIme)
{
    std::lock_guard<std::mutex> lock(stateLock_);
    isStarted_ = isStarted;
    currentTypeIme_ = currentIme;
}

bool InputTypeManager::IsStarted()
{
    std::lock_guard<std::mutex> lock(stateLock_);
    return isStarted_;
}
// LCOV_EXCL_START
bool InputTypeManager::IsSecurityImeStarted()
{
    InputType type = InputType::SECURITY_INPUT;
    return IsInputTypeImeStarted(type);
    std::lock_guard<std::mutex> lock(typesLock_);
}

bool InputTypeManager::IsCameraImeStarted()
{
    InputType type = InputType::CAMERA_INPUT;
    return IsInputTypeImeStarted(type);
}

bool InputTypeManager::IsVoiceImeStarted()
{
    InputType type = InputType::VOICE_INPUT;
    return IsInputTypeImeStarted(type);
}

bool InputTypeManager::IsVoiceKbImeStarted()
{
    InputType type = InputType::VOICEKB_INPUT;
    return IsInputTypeImeStarted(type);
}

bool InputTypeManager::IsInputTypeImeStarted(InputType type)
{
    if (!IsStarted()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(typesLock_);
    return inputTypes_.find(type) != inputTypes_.end() &&
           inputTypes_[type] == GetCurrentIme();
}

InputType InputTypeManager::GetCurrentInputType()
{
    if (IsSecurityImeStarted()) {
        return InputType::SECURITY_INPUT;
    }
    if (IsCameraImeStarted()) {
        return InputType::CAMERA_INPUT;
    }
    if (IsVoiceImeStarted()) {
        return InputType::VOICE_INPUT;
    }
    if (IsVoiceKbImeStarted()) {
        return InputType::VOICEKB_INPUT;
    }
    return InputType::NONE;
}

ImeIdentification InputTypeManager::GetCurrentIme()
{
    std::lock_guard<std::mutex> lock(stateLock_);
    return currentTypeIme_;
}
// LCOV_EXCL_STOP
bool InputTypeManager::Init()
{
    IMSA_HILOGD("start.");
    if (isInitInProgress_.load()) {
        return isInitSuccess_.GetValue();
    }
    isInitInProgress_.store(true);
    isInitSuccess_.Clear(false);
    std::vector<InputTypeInfo> configs;
    auto isSuccess = SysCfgParser::ParseInputType(configs);
    IMSA_HILOGD("ParseInputType isSuccess: %{public}d.", isSuccess);
    if (isSuccess) {
        std::lock_guard<std::mutex> lk(typesLock_);
        for (const auto &config : configs) {
            inputTypes_.insert({ config.type, { config.bundleName, config.subName } });
        }
        for (const auto &cfg : inputTypes_) {
            std::lock_guard<std::mutex> lock(listLock_);
            inputTypeImeList_.insert(cfg.second);
        }
    } else {
        std::lock_guard<std::mutex> lk(typesLock_);
        inputTypes_.clear();
    }
    isTypeCfgReady_.store(isSuccess);
    isInitSuccess_.SetValue(isSuccess);
    isInitInProgress_.store(false);
    return isSuccess;
}
} // namespace MiscServices
} // namespace OHOS