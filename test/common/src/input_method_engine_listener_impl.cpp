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

#include "input_method_engine_listener_impl.h"

#include "global.h"

namespace OHOS {
namespace MiscServices {
bool InputMethodEngineListenerImpl::keyboardState_ = false;
bool InputMethodEngineListenerImpl::isInputStart_ = false;
uint32_t InputMethodEngineListenerImpl::windowId_ = 0;
std::mutex InputMethodEngineListenerImpl::imeListenerMutex_;
std::condition_variable InputMethodEngineListenerImpl::imeListenerCv_;
bool InputMethodEngineListenerImpl::isEnable_{ false };
bool InputMethodEngineListenerImpl::isInputFinish_{ false };
void InputMethodEngineListenerImpl::OnKeyboardStatus(bool isShow)
{
    IMSA_HILOGI("InputMethodEngineListenerImpl::OnKeyboardStatus %{public}s", isShow ? "show" : "hide");
    keyboardState_ = isShow;
}
void InputMethodEngineListenerImpl::OnInputStart()
{
    IMSA_HILOGI("InputMethodEngineListenerImpl::OnInputStart");
    isInputStart_ = true;
    imeListenerCv_.notify_one();
}
void InputMethodEngineListenerImpl::OnInputStop()
{
    IMSA_HILOGI("InputMethodEngineListenerImpl::OnInputStop");
}
void InputMethodEngineListenerImpl::OnSetCallingWindow(uint32_t windowId)
{
    IMSA_HILOGI("InputMethodEngineListenerImpl::OnSetCallingWindow %{public}d", windowId);
    windowId_ = windowId;
}
void InputMethodEngineListenerImpl::OnSetSubtype(const SubProperty &property)
{
    IMSA_HILOGD("InputMethodEngineListenerImpl::OnSetSubtype");
}
void InputMethodEngineListenerImpl::OnInputFinish()
{
    IMSA_HILOGD("test");
    isInputFinish_ = true;
    imeListenerCv_.notify_one();
}
bool InputMethodEngineListenerImpl::IsEnable()
{
    IMSA_HILOGD("test::isEnable: %{public}d", isEnable_);
    return isEnable_;
}
void InputMethodEngineListenerImpl::ResetParam()
{
    isInputStart_ = false;
    isInputFinish_ = false;
}
bool InputMethodEngineListenerImpl::WaitInputStart()
{
    std::unique_lock<std::mutex> lock(imeListenerMutex_);
    imeListenerCv_.wait_for(lock, std::chrono::seconds(1), []() { return isInputStart_; });
    return isInputStart_;
}
bool InputMethodEngineListenerImpl::WaitInputFinish()
{
    std::unique_lock<std::mutex> lock(imeListenerMutex_);
    imeListenerCv_.wait_for(lock, std::chrono::seconds(1), []() { return isInputFinish_; });
    return isInputFinish_;
}
} // namespace MiscServices
} // namespace OHOS
