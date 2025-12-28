/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "input_method_controller.h"
#undef private

#include "ontextchangedlistener_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>

#include "event_handler.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "input_method_utils.h"
#include "text_listener.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace {
constexpr int32_t PRIVATE_DATA_VALUE = 100;
constexpr int32_t FUZZER_SUCCESS = 0;
}

class FuzzTextListener : public TextListener {
public:
    explicit FuzzTextListener(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
    {
        eventHandler_ = handler;
    }

    bool IsFromTs() override
    {
        return isFromTs_;
    }

    std::shared_ptr<AppExecFwk::EventHandler> GetEventHandler() override
    {
        return eventHandler_;
    }

    void SetIsFromTs(bool isFromTs)
    {
        isFromTs_ = isFromTs;
    }

private:
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_{ nullptr };
    bool isFromTs_{ false };
};

void FuzzFinishTextPreview(sptr<FuzzTextListener> listener)
{
    listener->FinishTextPreview();
    listener->FinishTextPreviewV2();
}

void FuzzOnDetach(sptr<FuzzTextListener> listener)
{
    listener->OnDetach();
    listener->OnDetachV2();
}

void FuzzIsFromTs(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    auto fuzzedBool = provider.ConsumeBool();
    listener->SetIsFromTs(fuzzedBool);
    listener->IsFromTs();
}

void FuzzGetEventHandler(sptr<FuzzTextListener> listener)
{
    listener->GetEventHandler();
}

void FuzzNotifyPanelStatusInfo(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    auto fuzzedBool = provider.ConsumeBool();
    PanelInfo panelInfo;
    panelInfo.panelType = static_cast<PanelType>(fuzzedBool);
    panelInfo.panelFlag = static_cast<PanelFlag>(fuzzedBool);
    PanelStatusInfo panelStatusInfo;
    panelStatusInfo.panelInfo = panelInfo;
    panelStatusInfo.visible = fuzzedBool;
    panelStatusInfo.trigger = Trigger::IME_APP;
    listener->NotifyPanelStatusInfo(panelStatusInfo);
    listener->NotifyPanelStatusInfoV2(panelStatusInfo);
}

void FuzzNotifyKeyboardHeight(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    auto fuzzedHeight = provider.ConsumeIntegral<uint32_t>();
    listener->NotifyKeyboardHeight(fuzzedHeight);
    listener->NotifyKeyboardHeightV2(fuzzedHeight);
}

void FuzzReceivePrivateCommand(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    auto fuzzedBool = provider.ConsumeBool();
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    PrivateDataValue privateDataValue1 = fuzzedString;
    PrivateDataValue privateDataValue2 = static_cast<int32_t>(fuzzedBool);
    PrivateDataValue privateDataValue3 = PRIVATE_DATA_VALUE;
    privateCommand.emplace("value1", privateDataValue1);
    privateCommand.emplace("value2", privateDataValue2);
    privateCommand.emplace("value3", privateDataValue3);
    listener->ReceivePrivateCommand(privateCommand);
    listener->ReceivePrivateCommandV2(privateCommand);
}

void FuzzSetPreviewText(sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto fuzzedStart = provider.ConsumeIntegral<int32_t>();
    auto fuzzedEnd = provider.ConsumeIntegral<int32_t>();
    Range range = { .start = fuzzedStart, .end = fuzzedEnd };
    listener->SetPreviewText(fuzzedU16String, range);
    listener->SetPreviewTextV2(fuzzedU16String, range);
}

void FuzzInputMethodControllerWithListener(sptr<InputMethodController> imc,
    sptr<FuzzTextListener> listener, FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto fuzzInt32 = provider.ConsumeIntegral<int32_t>();
    auto fuzzBool = provider.ConsumeBool();
    
    imc->clientInfo_.state = ClientState::ACTIVE;
    imc->SetTextListener(listener);
    imc->GetTextListener();
    imc->isEditable_.store(true);
    imc->isBound_.store(true);
    imc->IsEditable();
    imc->IsBound();

    imc->InsertText(fuzzedU16String);
    imc->DeleteForward(fuzzInt32);
    imc->DeleteBackward(fuzzInt32);
    imc->MoveCursor(Direction::UP);
    imc->SendKeyboardStatus(KeyboardStatus::SHOW);
    imc->SendFunctionKey(fuzzInt32);
    
    PanelStatusInfo panelStatusInfo;
    panelStatusInfo.panelInfo.panelType = PanelType::SOFT_KEYBOARD;
    panelStatusInfo.panelInfo.panelFlag = PanelFlag::FLG_FIXED;
    panelStatusInfo.visible = fuzzBool;
    panelStatusInfo.trigger = Trigger::IME_APP;
    panelStatusInfo.sessionId = FUZZER_SUCCESS;
    imc->NotifyPanelStatusInfo(panelStatusInfo);
    imc->NotifyKeyboardHeight(provider.ConsumeIntegral<uint32_t>());
    
    std::unordered_map<std::string, PrivateDataValue> privateCommand;
    privateCommand.emplace("key1", fuzzedString);
    privateCommand.emplace("key2", fuzzInt32);
    imc->ReceivePrivateCommand(privateCommand);
}

void FuzzOnTextChangedListenerV2Methods(FuzzedDataProvider &provider)
{
    std::string fuzzedString = provider.ConsumeRandomLengthString();
    std::u16string fuzzedU16String(fuzzedString.begin(), fuzzedString.end());
    auto fuzzInt32 = provider.ConsumeIntegral<int32_t>();
    auto fuzzBool = provider.ConsumeBool();
    
    std::shared_ptr<AppExecFwk::EventRunner> runner =
        AppExecFwk::EventRunner::Create("fuzzV2Handler");
    auto handler = std::make_shared<AppExecFwk::EventHandler>(runner);
    sptr<FuzzTextListener> v2Listener =
        new (std::nothrow) FuzzTextListener(handler);
    if (v2Listener == nullptr) {
        return;
    }
    
    v2Listener->InsertTextV2(fuzzedU16String);
    v2Listener->DeleteForwardV2(fuzzInt32);
    v2Listener->DeleteBackwardV2(fuzzInt32);
    v2Listener->SendKeyboardStatusV2(KeyboardStatus::SHOW);
    FunctionKey functionKey;
    v2Listener->SendFunctionKeyV2(functionKey);
    v2Listener->MoveCursorV2(Direction::DOWN);
    v2Listener->HandleExtendActionV2(fuzzInt32);
    v2Listener->GetLeftTextOfCursorV2(fuzzInt32);
    v2Listener->GetRightTextOfCursorV2(fuzzInt32);
    v2Listener->GetTextIndexAtCursorV2();
    KeyEvent keyEvent;
    v2Listener->SendKeyEventFromInputMethodV2(keyEvent);
    v2Listener->SetKeyboardStatusV2(fuzzBool);
    v2Listener->HandleSetSelectionV2(fuzzInt32, fuzzInt32);
    v2Listener->HandleSelectV2(fuzzInt32, fuzzInt32);
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == OHOS::FUZZER_SUCCESS) {
        return OHOS::FUZZER_SUCCESS;
    }

    FuzzedDataProvider provider(data, size);
    std::shared_ptr<OHOS::AppExecFwk::EventRunner> runner =
        OHOS::AppExecFwk::EventRunner::Create("fuzzTextListenerHandler");
    auto handler = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    OHOS::sptr<OHOS::FuzzTextListener> listener =
        new (std::nothrow) OHOS::FuzzTextListener(handler);
    if (listener == nullptr) {
        return OHOS::FUZZER_SUCCESS;
    }

    OHOS::sptr<OHOS::MiscServices::InputMethodController> imc =
        OHOS::MiscServices::InputMethodController::GetInstance();
    if (imc != nullptr) {
        OHOS::FuzzInputMethodControllerWithListener(imc, listener, provider);
    }

    OHOS::FuzzFinishTextPreview(listener);
    OHOS::FuzzOnDetach(listener);
    OHOS::FuzzIsFromTs(listener, provider);
    OHOS::FuzzGetEventHandler(listener);
    OHOS::FuzzNotifyPanelStatusInfo(listener, provider);
    OHOS::FuzzNotifyKeyboardHeight(listener, provider);
    OHOS::FuzzReceivePrivateCommand(listener, provider);
    OHOS::FuzzSetPreviewText(listener, provider);
    OHOS::FuzzOnTextChangedListenerV2Methods(provider);
    return OHOS::FUZZER_SUCCESS;
}
