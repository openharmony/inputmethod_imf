/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "ime_event_monitor_manager_impl.h"

#include <algorithm>

#include "input_method_controller.h"
#include "event_status_manager.h"

namespace OHOS {
namespace MiscServices {
ImeEventMonitorManagerImpl::ImeEventMonitorManagerImpl() { }

ImeEventMonitorManagerImpl::~ImeEventMonitorManagerImpl() { }

ImeEventMonitorManagerImpl &ImeEventMonitorManagerImpl::GetInstance()
{
    static ImeEventMonitorManagerImpl manager;
    return manager;
}

int32_t ImeEventMonitorManagerImpl::RegisterImeEventListener(
    uint32_t eventFlag, const std::shared_ptr<ImeEventListener> &listener)
{
    std::lock_guard<std::mutex> lock(lock_);
    uint32_t currentEventFlag = 0;
    for (const auto &listenerTemp : listeners_) {
        currentEventFlag |= listenerTemp.first;
    }
    auto finalEventFlag = currentEventFlag | eventFlag;
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }

    auto ret = instance->UpdateListenEventFlag(finalEventFlag, eventFlag, true);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to UpdateListenEventFlag: %{public}d!", ret);
        return ret;
    }
    for (uint32_t i = 0; i < MAX_EVENT_NUM; i++) {
        auto eventMask = eventFlag & (1u << i);
        if (eventMask == 0) {
            continue;
        }
        auto it = listeners_.find(eventMask);
        if (it == listeners_.end()) {
            listeners_.insert({ eventMask, { listener } });
            continue;
        }
        it->second.insert(listener);
    }
    // Register inputStart callback when imf bound, need inputStart callback when register finish
    if (EventStatusManager::IsInputStatusChangedOn(eventFlag)) {
        bool isInputStart = false;
        uint32_t callingWindowId = 0;
        int32_t requestKeyboardReason = 0;
        auto ret = instance->GetInputStartInfo(isInputStart, callingWindowId, requestKeyboardReason);
        if (ret == ErrorCode::NO_ERROR && isInputStart && listener != nullptr) {
            listener->OnInputStart(callingWindowId, requestKeyboardReason);
        }
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventMonitorManagerImpl::UnRegisterImeEventListener(
    uint32_t eventFlag, const std::shared_ptr<ImeEventListener> &listener)
{
    std::lock_guard<std::mutex> lock(lock_);
    bool isAbsentParam = false;
    for (uint32_t i = 0; i < MAX_EVENT_NUM; i++) {
        auto eventMask = eventFlag & (1u << i);
        if (eventMask == 0) {
            continue;
        }
        auto it = listeners_.find(eventMask);
        if (it == listeners_.end()) {
            isAbsentParam = true;
            continue;
        }
        auto iter = it->second.find(listener);
        if (iter == it->second.end()) {
            isAbsentParam = true;
            continue;
        }
        it->second.erase(iter);
        if (it->second.empty()) {
            listeners_.erase(it);
        }
    }
    uint32_t finalEventFlag = 0;
    for (const auto &listenerTemp : listeners_) {
        finalEventFlag |= listenerTemp.first;
    }
    auto instance = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("failed to get InputMethodController instance!");
        return ErrorCode::ERROR_EX_NULL_POINTER;
    }
    auto ret = instance->UpdateListenEventFlag(finalEventFlag, eventFlag, false);
    if (ret != ErrorCode::NO_ERROR) {
        IMSA_HILOGE("failed to UpdateListenEventFlag: %{public}d!", ret);
        return ret;
    }
    return isAbsentParam ? ErrorCode::ERROR_BAD_PARAMETERS : ErrorCode::NO_ERROR;
}

int32_t ImeEventMonitorManagerImpl::OnImeChange(const Property &property, const SubProperty &subProperty)
{
    auto listeners = GetListeners(EVENT_IME_CHANGE_MASK);
    for (const auto &listener : listeners) {
        listener->OnImeChange(property, subProperty);
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventMonitorManagerImpl::OnPanelStatusChange(const InputWindowStatus &status, const ImeWindowInfo &info)
{
    if (status == InputWindowStatus::HIDE) {
        return OnImeHide(info);
    }
    if (status == InputWindowStatus::SHOW) {
        return OnImeShow(info);
    }
    return ErrorCode::ERROR_BAD_PARAMETERS;
}

int32_t ImeEventMonitorManagerImpl::OnInputStart(uint32_t callingWndId, int32_t requestKeyboardReason)
{
    isInputStart_ = true;
    callingWindow_ = callingWndId;
    requestKeyboardReason_ = requestKeyboardReason;
    auto listeners = GetListeners(EVENT_INPUT_STATUS_CHANGED_MASK);
    for (const auto &listener : listeners) {
        if (listener != nullptr) {
            IMSA_HILOGD("listener start to callback, callingWndId: %{public}u", callingWndId);
            listener->OnInputStart(callingWndId, requestKeyboardReason);
        }
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventMonitorManagerImpl::OnInputStop()
{
    isInputStart_ = false;
    auto listeners = GetListeners(EVENT_INPUT_STATUS_CHANGED_MASK);
    for (const auto &listener : listeners) {
        if (listener != nullptr) {
            listener->OnInputStop();
        }
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventMonitorManagerImpl::OnImeShow(const ImeWindowInfo &info)
{
    auto listeners = GetListeners(EVENT_IME_SHOW_MASK);
    for (const auto &listener : listeners) {
        listener->OnImeShow(info);
    }
    return ErrorCode::NO_ERROR;
}

int32_t ImeEventMonitorManagerImpl::OnImeHide(const ImeWindowInfo &info)
{
    auto listeners = GetListeners(EVENT_IME_HIDE_MASK);
    for (const auto &listener : listeners) {
        listener->OnImeHide(info);
    }
    return ErrorCode::NO_ERROR;
}

std::set<std::shared_ptr<ImeEventListener>> ImeEventMonitorManagerImpl::GetListeners(uint32_t eventMask)
{
    std::lock_guard<std::mutex> lock(lock_);
    auto it = listeners_.find(eventMask);
    if (it == listeners_.end()) {
        return {};
    }
    return it->second;
}
} // namespace MiscServices
} // namespace OHOS