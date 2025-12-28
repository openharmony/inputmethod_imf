/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "listenerapis_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <variant>

#include "fuzzer/FuzzedDataProvider.h"
#include "global.h"
#include "ime_event_listener.h"
#include "input_attribute.h"
#include "input_method_controller.h"
#include "input_method_engine_listener.h"
#include "input_method_property.h"
#include "input_method_utils.h"
#include "input_window_info.h"
#include "message_parcel.h"
#include "panel_info.h"

using namespace OHOS::MiscServices;

namespace OHOS {
namespace MiscServices {

// ============================================================================
// Part 1: InputMethodEngineListener Implementation for Fuzz Testing
// ============================================================================
class FuzzInputMethodEngineListener : public InputMethodEngineListener {
public:
    FuzzInputMethodEngineListener() = default;
    ~FuzzInputMethodEngineListener() override = default;

    // Pure virtual functions that must be implemented
    void OnKeyboardStatus(bool isShow) override
    {
        keyboardStatus_ = isShow;
    }

    void OnInputStart() override
    {
        inputStarted_ = true;
    }

    int32_t OnInputStop() override
    {
        inputStarted_ = false;
        return ErrorCode::NO_ERROR;
    }

    void OnSetCallingWindow(uint32_t windowId) override
    {
        callingWindowId_ = windowId;
    }

    void OnSetSubtype(const SubProperty &property) override
    {
        subProperty_ = property;
    }

    void ReceivePrivateCommand(const std::unordered_map<std::string, PrivateDataValue> &privateCommand) override
    {
        privateCommand_ = privateCommand;
    }

    // Target APIs to be fuzz tested
    int32_t OnDiscardTypingText() override
    {
        discardTypingTextCalled_ = true;
        return discardTypingTextResult_;
    }

    void OnSecurityChange(int32_t security) override
    {
        securityLevel_ = security;
    }

    void OnInputFinish() override
    {
        inputFinished_ = true;
    }

    bool IsEnable() override
    {
        return isEnabled_;
    }

    bool IsCallbackRegistered(const std::string &type) override
    {
        auto it = registeredCallbacks_.find(type);
        return it != registeredCallbacks_.end() && it->second;
    }

    bool PostTaskToEventHandler(std::function<void()> task, const std::string &taskName) override
    {
        if (task && postTaskEnabled_) {
            task();
            lastTaskName_ = taskName;
            return true;
        }
        return false;
    }

    void OnCallingDisplayIdChanged(uint64_t callingDisplayId) override
    {
        callingDisplayId_ = callingDisplayId;
    }

    void NotifyPreemption() override
    {
        preemptionNotified_ = true;
    }

    // Setters for fuzz testing
    void SetDiscardTypingTextResult(int32_t result) { discardTypingTextResult_ = result; }
    void SetIsEnabled(bool enabled) { isEnabled_ = enabled; }
    void SetPostTaskEnabled(bool enabled) { postTaskEnabled_ = enabled; }
    void RegisterCallback(const std::string &type, bool registered) { registeredCallbacks_[type] = registered; }

    // Getters for verification
    bool GetKeyboardStatus() const { return keyboardStatus_; }
    bool GetInputStarted() const { return inputStarted_; }
    uint32_t GetCallingWindowId() const { return callingWindowId_; }
    int32_t GetSecurityLevel() const { return securityLevel_; }
    bool GetInputFinished() const { return inputFinished_; }
    uint64_t GetCallingDisplayId() const { return callingDisplayId_; }
    bool GetPreemptionNotified() const { return preemptionNotified_; }
    bool GetDiscardTypingTextCalled() const { return discardTypingTextCalled_; }
    std::string GetLastTaskName() const { return lastTaskName_; }

private:
    bool keyboardStatus_ = false;
    bool inputStarted_ = false;
    uint32_t callingWindowId_ = 0;
    SubProperty subProperty_;
    std::unordered_map<std::string, PrivateDataValue> privateCommand_;
    int32_t discardTypingTextResult_ = ErrorCode::NO_ERROR;
    bool discardTypingTextCalled_ = false;
    int32_t securityLevel_ = 0;
    bool inputFinished_ = false;
    bool isEnabled_ = true;
    std::unordered_map<std::string, bool> registeredCallbacks_;
    bool postTaskEnabled_ = true;
    std::string lastTaskName_;
    uint64_t callingDisplayId_ = 0;
    bool preemptionNotified_ = false;
};

// ============================================================================
// Part 2: ImeEventListener Implementation for Fuzz Testing
// ============================================================================
class FuzzImeEventListener : public ImeEventListener {
public:
    FuzzImeEventListener() = default;
    ~FuzzImeEventListener() override = default;

    // Target APIs to be fuzz tested
    void OnImeChange(const Property &property, const SubProperty &subProperty) override
    {
        imeChangeProperty_ = property;
        imeChangeSubProperty_ = subProperty;
        imeChangeCalled_ = true;
    }

    void OnImeShow(const ImeWindowInfo &info) override
    {
        imeShowInfo_ = info;
        imeShowCalled_ = true;
    }

    void OnImeHide(const ImeWindowInfo &info) override
    {
        imeHideInfo_ = info;
        imeHideCalled_ = true;
    }

    void OnInputStart(uint32_t callingWndId, int32_t requestKeyboardReason) override
    {
        inputStartCallingWndId_ = callingWndId;
        inputStartKeyboardReason_ = requestKeyboardReason;
        inputStartCalled_ = true;
    }

    void OnInputStop() override
    {
        inputStopCalled_ = true;
    }

    // Getters for verification
    bool GetImeChangeCalled() const { return imeChangeCalled_; }
    bool GetImeShowCalled() const { return imeShowCalled_; }
    bool GetImeHideCalled() const { return imeHideCalled_; }
    bool GetInputStartCalled() const { return inputStartCalled_; }
    bool GetInputStopCalled() const { return inputStopCalled_; }
    uint32_t GetInputStartCallingWndId() const { return inputStartCallingWndId_; }
    int32_t GetInputStartKeyboardReason() const { return inputStartKeyboardReason_; }

private:
    Property imeChangeProperty_;
    SubProperty imeChangeSubProperty_;
    bool imeChangeCalled_ = false;
    ImeWindowInfo imeShowInfo_;
    bool imeShowCalled_ = false;
    ImeWindowInfo imeHideInfo_;
    bool imeHideCalled_ = false;
    uint32_t inputStartCallingWndId_ = 0;
    int32_t inputStartKeyboardReason_ = 0;
    bool inputStartCalled_ = false;
    bool inputStopCalled_ = false;
};

// ============================================================================
// Part 3: OnTextChangedListener Implementation for Fuzz Testing
// ============================================================================
class FuzzTextChangedListener : public OnTextChangedListener {
public:
    FuzzTextChangedListener() = default;
    ~FuzzTextChangedListener() override = default;

    // Pure virtual functions that must be implemented
    void InsertText(const std::u16string &text) override { insertedText_ = text; }
    void DeleteForward(int32_t length) override { deleteForwardLength_ = length; }
    void DeleteBackward(int32_t length) override { deleteBackwardLength_ = length; }
    void SendKeyEventFromInputMethod(const KeyEvent &event) override { lastKeyEvent_ = event; }
    void SendKeyboardStatus(const KeyboardStatus &keyboardStatus) override { keyboardStatus_ = keyboardStatus; }
    void SendFunctionKey(const FunctionKey &functionKey) override { lastFunctionKey_ = functionKey; }
    void SetKeyboardStatus(bool status) override { keyboardVisible_ = status; }
    void MoveCursor(const Direction direction) override { cursorDirection_ = direction; }
    void HandleSetSelection(int32_t start, int32_t end) override { selectionStart_ = start; selectionEnd_ = end; }
    void HandleExtendAction(int32_t action) override { extendAction_ = action; }
    void HandleSelect(int32_t keyCode, int32_t cursorMoveSkip) override {
        selectKeyCode_ = keyCode;
        selectCursorMoveSkip_ = cursorMoveSkip;
    }
    std::u16string GetLeftTextOfCursor(int32_t number) override { return leftText_; }
    std::u16string GetRightTextOfCursor(int32_t number) override { return rightText_; }
    int32_t GetTextIndexAtCursor() override { return textIndex_; }

    // Target APIs to be fuzz tested
    void FinishTextPreview() override
    {
        finishTextPreviewCalled_ = true;
    }

    void OnDetach() override
    {
        onDetachCalled_ = true;
    }

    // Setters for fuzz testing
    void SetLeftText(const std::u16string &text) { leftText_ = text; }
    void SetRightText(const std::u16string &text) { rightText_ = text; }
    void SetTextIndex(int32_t index) { textIndex_ = index; }

    // Getters for verification
    bool GetFinishTextPreviewCalled() const { return finishTextPreviewCalled_; }
    bool GetOnDetachCalled() const { return onDetachCalled_; }
    std::u16string GetInsertedText() const { return insertedText_; }
    int32_t GetDeleteForwardLength() const { return deleteForwardLength_; }
    int32_t GetDeleteBackwardLength() const { return deleteBackwardLength_; }

private:
    std::u16string insertedText_;
    int32_t deleteForwardLength_ = 0;
    int32_t deleteBackwardLength_ = 0;
    KeyEvent lastKeyEvent_;
    KeyboardStatus keyboardStatus_ = KeyboardStatus::NONE;
    FunctionKey lastFunctionKey_;
    bool keyboardVisible_ = false;
    Direction cursorDirection_ = Direction::NONE;
    int32_t selectionStart_ = 0;
    int32_t selectionEnd_ = 0;
    int32_t extendAction_ = 0;
    int32_t selectKeyCode_ = 0;
    int32_t selectCursorMoveSkip_ = 0;
    std::u16string leftText_;
    std::u16string rightText_;
    int32_t textIndex_ = 0;
    bool finishTextPreviewCalled_ = false;
    bool onDetachCalled_ = false;
};

} // namespace MiscServices

// ============================================================================
// Part 4: Fuzz Test Functions for InputMethodEngineListener
// ============================================================================
void FuzzOnDiscardTypingText(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    int32_t fuzzedResult = provider.ConsumeIntegral<int32_t>();
    listener->SetDiscardTypingTextResult(fuzzedResult);
    int32_t result = listener->OnDiscardTypingText();
    (void)result;
}

void FuzzOnSecurityChange(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    int32_t fuzzedSecurity = provider.ConsumeIntegral<int32_t>();
    listener->OnSecurityChange(fuzzedSecurity);
}

void FuzzOnInputFinish(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    listener->OnInputFinish();
}

void FuzzIsEnable(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    bool fuzzedEnabled = provider.ConsumeBool();
    listener->SetIsEnabled(fuzzedEnabled);
    bool result = listener->IsEnable();
    (void)result;
}

void FuzzIsCallbackRegistered(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    std::string fuzzedType = provider.ConsumeRandomLengthString(100);
    bool fuzzedRegistered = provider.ConsumeBool();
    listener->RegisterCallback(fuzzedType, fuzzedRegistered);
    bool result = listener->IsCallbackRegistered(fuzzedType);
    (void)result;

    // Test with different callback types
    std::string anotherType = provider.ConsumeRandomLengthString(50);
    result = listener->IsCallbackRegistered(anotherType);
    (void)result;
}

void FuzzPostTaskToEventHandler(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    bool fuzzedPostTaskEnabled = provider.ConsumeBool();
    listener->SetPostTaskEnabled(fuzzedPostTaskEnabled);

    std::string fuzzedTaskName = provider.ConsumeRandomLengthString(100);
    bool taskExecuted = false;
    std::function<void()> task = [&taskExecuted]() {
        taskExecuted = true;
    };

    bool result = listener->PostTaskToEventHandler(task, fuzzedTaskName);
    (void)result;

    // Test with null task
    result = listener->PostTaskToEventHandler(nullptr, fuzzedTaskName);
    (void)result;
}

void FuzzOnCallingDisplayIdChanged(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    uint64_t fuzzedDisplayId = provider.ConsumeIntegral<uint64_t>();
    listener->OnCallingDisplayIdChanged(fuzzedDisplayId);
}

void FuzzNotifyPreemption(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
    listener->NotifyPreemption();
}

// ============================================================================
// Part 5: Fuzz Test Functions for ImeEventListener
// ============================================================================
void FuzzOnImeChange(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzImeEventListener>();

    MiscServices::Property property;
    property.name = provider.ConsumeRandomLengthString(50);
    property.id = provider.ConsumeRandomLengthString(50);
    property.label = provider.ConsumeRandomLengthString(50);
    property.labelId = provider.ConsumeIntegral<uint32_t>();
    property.icon = provider.ConsumeRandomLengthString(50);
    property.iconId = provider.ConsumeIntegral<uint32_t>();

    MiscServices::SubProperty subProperty;
    subProperty.name = provider.ConsumeRandomLengthString(50);
    subProperty.id = provider.ConsumeRandomLengthString(50);
    subProperty.label = provider.ConsumeRandomLengthString(50);
    subProperty.labelId = provider.ConsumeIntegral<uint32_t>();
    subProperty.icon = provider.ConsumeRandomLengthString(50);
    subProperty.iconId = provider.ConsumeIntegral<uint32_t>();
    subProperty.mode = provider.ConsumeRandomLengthString(20);
    subProperty.locale = provider.ConsumeRandomLengthString(20);
    subProperty.language = provider.ConsumeRandomLengthString(20);

    listener->OnImeChange(property, subProperty);
}

void FuzzOnImeShow(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzImeEventListener>();

    MiscServices::ImeWindowInfo info;
    info.panelInfo.panelType = static_cast<MiscServices::PanelType>(provider.ConsumeIntegral<uint32_t>());
    info.panelInfo.panelFlag = static_cast<MiscServices::PanelFlag>(provider.ConsumeIntegral<uint32_t>());
    info.windowInfo.left = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.top = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.width = provider.ConsumeIntegral<uint32_t>();
    info.windowInfo.height = provider.ConsumeIntegral<uint32_t>();

    listener->OnImeShow(info);
}

void FuzzOnImeHide(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzImeEventListener>();

    MiscServices::ImeWindowInfo info;
    info.panelInfo.panelType = static_cast<MiscServices::PanelType>(provider.ConsumeIntegral<uint32_t>());
    info.panelInfo.panelFlag = static_cast<MiscServices::PanelFlag>(provider.ConsumeIntegral<uint32_t>());
    info.windowInfo.left = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.top = provider.ConsumeIntegral<int32_t>();
    info.windowInfo.width = provider.ConsumeIntegral<uint32_t>();
    info.windowInfo.height = provider.ConsumeIntegral<uint32_t>();

    listener->OnImeHide(info);
}

void FuzzOnInputStart(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzImeEventListener>();
    uint32_t fuzzedCallingWndId = provider.ConsumeIntegral<uint32_t>();
    int32_t fuzzedKeyboardReason = provider.ConsumeIntegral<int32_t>();
    listener->OnInputStart(fuzzedCallingWndId, fuzzedKeyboardReason);
}

void FuzzOnInputStop(FuzzedDataProvider &provider)
{
    auto listener = std::make_shared<MiscServices::FuzzImeEventListener>();
    listener->OnInputStop();
}

// ============================================================================
// Part 6: Fuzz Test Functions for OnTextChangedListener
// ============================================================================
void FuzzFinishTextPreview(FuzzedDataProvider &provider)
{
    sptr<MiscServices::FuzzTextChangedListener> listener = new MiscServices::FuzzTextChangedListener();

    // Test basic FinishTextPreview call
    listener->FinishTextPreview();

    // Set some fuzzed state before calling
    std::string fuzzedLeftText = provider.ConsumeRandomLengthString(100);
    std::string fuzzedRightText = provider.ConsumeRandomLengthString(100);
    int32_t fuzzedTextIndex = provider.ConsumeIntegral<int32_t>();

    listener->SetLeftText(std::u16string(fuzzedLeftText.begin(), fuzzedLeftText.end()));
    listener->SetRightText(std::u16string(fuzzedRightText.begin(), fuzzedRightText.end()));
    listener->SetTextIndex(fuzzedTextIndex);

    // Call again with state set
    listener->FinishTextPreview();
}

void FuzzOnDetach(FuzzedDataProvider &provider)
{
    sptr<MiscServices::FuzzTextChangedListener> listener = new MiscServices::FuzzTextChangedListener();

    // Test basic OnDetach call
    listener->OnDetach();

    // Create another instance with fuzzed state
    sptr<MiscServices::FuzzTextChangedListener> listener2 = new MiscServices::FuzzTextChangedListener();
    std::string fuzzedText = provider.ConsumeRandomLengthString(200);
    listener2->SetLeftText(std::u16string(fuzzedText.begin(), fuzzedText.end()));
    listener2->OnDetach();
}

// ============================================================================
// Part 7: Comprehensive Fuzz Test combining multiple APIs
// ============================================================================
void FuzzCombinedScenario(FuzzedDataProvider &provider)
{
    uint8_t scenario = provider.ConsumeIntegral<uint8_t>() % 5;

    switch (scenario) {
        case 0: {
            // Scenario 1: Full InputMethodEngineListener lifecycle
            auto engineListener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
            engineListener->OnInputStart();
            engineListener->OnSecurityChange(provider.ConsumeIntegral<int32_t>());
            engineListener->OnCallingDisplayIdChanged(provider.ConsumeIntegral<uint64_t>());

            std::string taskName = provider.ConsumeRandomLengthString(50);
            engineListener->PostTaskToEventHandler([]() {}, taskName);

            engineListener->OnDiscardTypingText();
            engineListener->OnInputFinish();
            engineListener->NotifyPreemption();
            engineListener->OnInputStop();
            break;
        }
        case 1: {
            // Scenario 2: ImeEventListener full cycle
            auto imeListener = std::make_shared<MiscServices::FuzzImeEventListener>();
            MiscServices::Property prop;
            prop.name = provider.ConsumeRandomLengthString(30);
            MiscServices::SubProperty subProp;
            subProp.name = provider.ConsumeRandomLengthString(30);
            imeListener->OnImeChange(prop, subProp);

            MiscServices::ImeWindowInfo windowInfo;
            windowInfo.windowInfo.width = provider.ConsumeIntegral<uint32_t>();
            windowInfo.windowInfo.height = provider.ConsumeIntegral<uint32_t>();

            imeListener->OnInputStart(provider.ConsumeIntegral<uint32_t>(), provider.ConsumeIntegral<int32_t>());
            imeListener->OnImeShow(windowInfo);
            imeListener->OnImeHide(windowInfo);
            imeListener->OnInputStop();
            break;
        }
        case 2: {
            // Scenario 3: TextChangedListener with preview
            sptr<MiscServices::FuzzTextChangedListener> textListener = new MiscServices::FuzzTextChangedListener();
            std::string inputText = provider.ConsumeRandomLengthString(100);
            textListener->InsertText(std::u16string(inputText.begin(), inputText.end()));
            textListener->FinishTextPreview();
            textListener->OnDetach();
            break;
        }
        case 3: {
            // Scenario 4: IsCallbackRegistered with various types
            auto engineListener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
            std::vector<std::string> callbackTypes = {"keyboardStatus", "inputStart", "inputStop",
                provider.ConsumeRandomLengthString(20)};
            for (const auto &type : callbackTypes) {
                engineListener->RegisterCallback(type, provider.ConsumeBool());
                engineListener->IsCallbackRegistered(type);
            }
            break;
        }
        case 4: {
            // Scenario 5: Stress test with multiple listeners
            for (int i = 0; i < 3; i++) {
                auto listener = std::make_shared<MiscServices::FuzzInputMethodEngineListener>();
                listener->SetIsEnabled(provider.ConsumeBool());
                listener->IsEnable();
                listener->OnSecurityChange(provider.ConsumeIntegral<int32_t>());
                listener->OnInputFinish();
            }
            break;
        }
        default:
            break;
    }
}

// ============================================================================
// Part 8: Fuzz Test Functions for Parcel Serialization/Deserialization
// ============================================================================
void FuzzTextSelectionInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    // Write fuzzed data as int32 values
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>()); // oldBegin
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>()); // oldEnd
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>()); // newBegin
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>()); // newEnd
    parcel.RewindRead(0);

    TextSelectionInner *result = TextSelectionInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzTextSelectionInnerMarshalling(FuzzedDataProvider &provider)
{
    TextSelectionInner selection;
    selection.oldBegin = provider.ConsumeIntegral<int32_t>();
    selection.oldEnd = provider.ConsumeIntegral<int32_t>();
    selection.newBegin = provider.ConsumeIntegral<int32_t>();
    selection.newEnd = provider.ConsumeIntegral<int32_t>();

    MessageParcel parcel;
    selection.Marshalling(parcel);
}

void FuzzValueUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    uint32_t mapSize = provider.ConsumeIntegralInRange<uint32_t>(0, 10);
    parcel.WriteUint32(mapSize);

    for (uint32_t i = 0; i < mapSize; i++) {
        std::string key = provider.ConsumeRandomLengthString(50);
        parcel.WriteString(key);
        int32_t valueType = provider.ConsumeIntegralInRange<int32_t>(0, 2);
        parcel.WriteInt32(valueType);
        if (valueType == 0) { // STRING
            parcel.WriteString(provider.ConsumeRandomLengthString(50));
        } else if (valueType == 1) { // BOOL
            parcel.WriteBool(provider.ConsumeBool());
        } else { // NUMBER
            parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
        }
    }
    parcel.RewindRead(0);

    Value *result = Value::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

// Test Value with non-empty map to cover the for loop
void FuzzValueWithNonEmptyMap(FuzzedDataProvider &provider)
{
    // Test case 1: map with STRING values
    {
        MessageParcel parcel;
        parcel.WriteUint32(2); // size = 2
        parcel.WriteString("key1");
        parcel.WriteInt32(0); // VALUE_TYPE_STRING
        parcel.WriteString(provider.ConsumeRandomLengthString(20));
        parcel.WriteString("key2");
        parcel.WriteInt32(0); // VALUE_TYPE_STRING
        parcel.WriteString(provider.ConsumeRandomLengthString(20));
        parcel.RewindRead(0);

        Value *result = Value::Unmarshalling(parcel);
        if (result != nullptr) {
            delete result;
        }
    }

    // Test case 2: map with BOOL values
    {
        MessageParcel parcel;
        parcel.WriteUint32(2);
        parcel.WriteString("boolKey1");
        parcel.WriteInt32(1); // VALUE_TYPE_BOOL
        parcel.WriteBool(provider.ConsumeBool());
        parcel.WriteString("boolKey2");
        parcel.WriteInt32(1); // VALUE_TYPE_BOOL
        parcel.WriteBool(provider.ConsumeBool());
        parcel.RewindRead(0);

        Value *result = Value::Unmarshalling(parcel);
        if (result != nullptr) {
            delete result;
        }
    }

    // Test case 3: map with NUMBER values
    {
        MessageParcel parcel;
        parcel.WriteUint32(2);
        parcel.WriteString("numKey1");
        parcel.WriteInt32(2); // VALUE_TYPE_NUMBER
        parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
        parcel.WriteString("numKey2");
        parcel.WriteInt32(2); // VALUE_TYPE_NUMBER
        parcel.WriteInt32(provider.ConsumeIntegral<int32_t>());
        parcel.RewindRead(0);

        Value *result = Value::Unmarshalling(parcel);
        if (result != nullptr) {
            delete result;
        }
    }

    // Test case 4: mixed value types
    {
        MessageParcel parcel;
        parcel.WriteUint32(3);
        parcel.WriteString("strKey");
        parcel.WriteInt32(0);
        parcel.WriteString("testString");
        parcel.WriteString("boolKey");
        parcel.WriteInt32(1);
        parcel.WriteBool(true);
        parcel.WriteString("numKey");
        parcel.WriteInt32(2);
        parcel.WriteInt32(12345);
        parcel.RewindRead(0);

        Value *result = Value::Unmarshalling(parcel);
        if (result != nullptr) {
            delete result;
        }
    }
}

void FuzzCursorInfoInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>()); // left
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>()); // top
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>()); // width
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>()); // height
    parcel.RewindRead(0);

    CursorInfoInner *result = CursorInfoInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzRangeInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>()); // start
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>()); // end
    parcel.RewindRead(0);

    RangeInner *result = RangeInner::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

void FuzzArrayBufferUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    parcel.WriteUint64(provider.ConsumeIntegral<uint64_t>()); // jsArgc
    parcel.WriteString(provider.ConsumeRandomLengthString(100)); // msgId
    std::vector<uint8_t> msgParam = provider.ConsumeBytes<uint8_t>(
        provider.ConsumeIntegralInRange<size_t>(0, 100));
    parcel.WriteUInt8Vector(msgParam);
    parcel.RewindRead(0);

    ArrayBuffer *result = ArrayBuffer::Unmarshalling(parcel);
    if (result != nullptr) {
        delete result;
    }
}

// Test PanelStatusInfoInner serialization/deserialization
void FuzzPanelStatusInfoInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    
    // Write PanelInfo (which is a Parcelable)
    // PanelInfo contains: panelType (enum) and panelFlag (enum)
    PanelInfo panelInfo;
    panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegralInRange<uint32_t>(0, 3));
    panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegralInRange<uint32_t>(0, 3));
    parcel.WriteParcelable(&panelInfo);
    
    parcel.WriteBool(provider.ConsumeBool()); // visible
    parcel.WriteInt32(provider.ConsumeIntegralInRange<int32_t>(0, 2)); // trigger
    parcel.WriteUint32(provider.ConsumeIntegral<uint32_t>()); // sessionId
    parcel.RewindRead(0);

    PanelStatusInfoInner *result = PanelStatusInfoInner::Unmarshalling(parcel);
    if (result != nullptr) {
        // Test Marshalling as well
        MessageParcel outParcel;
        result->Marshalling(outParcel);
        delete result;
    }
}

// Test TextTotalConfigInner serialization/deserialization
void FuzzTextTotalConfigInnerUnmarshalling(FuzzedDataProvider &provider)
{
    MessageParcel parcel;
    
    // Write InputAttributeInner
    InputAttributeInner inputAttr;
    inputAttr.inputPattern = provider.ConsumeIntegral<int32_t>();
    inputAttr.enterKeyType = provider.ConsumeIntegral<int32_t>();
    inputAttr.inputOption = provider.ConsumeIntegral<int32_t>();
    parcel.WriteParcelable(&inputAttr);
    
    // Write CursorInfoInner
    CursorInfoInner cursorInfo;
    cursorInfo.left = provider.ConsumeFloatingPoint<double>();
    cursorInfo.top = provider.ConsumeFloatingPoint<double>();
    cursorInfo.width = provider.ConsumeFloatingPoint<double>();
    cursorInfo.height = provider.ConsumeFloatingPoint<double>();
    parcel.WriteParcelable(&cursorInfo);
    
    // Write TextSelectionInner
    TextSelectionInner textSelection;
    textSelection.oldBegin = provider.ConsumeIntegral<int32_t>();
    textSelection.oldEnd = provider.ConsumeIntegral<int32_t>();
    textSelection.newBegin = provider.ConsumeIntegral<int32_t>();
    textSelection.newEnd = provider.ConsumeIntegral<int32_t>();
    parcel.WriteParcelable(&textSelection);
    
    parcel.WriteUint32(provider.ConsumeIntegral<uint32_t>()); // windowId
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>()); // positionY
    parcel.WriteDouble(provider.ConsumeFloatingPoint<double>()); // height
    
    // Write Value (commandValue)
    Value cmdValue;
    parcel.WriteParcelable(&cmdValue);
    
    parcel.WriteInt32(provider.ConsumeIntegral<int32_t>()); // requestKeyboardReason
    // Skip abilityToken (RemoteObject) for simplicity
    parcel.WriteBool(provider.ConsumeBool()); // isSimpleKeyboardEnabled
    parcel.RewindRead(0);

    TextTotalConfigInner *result = TextTotalConfigInner::Unmarshalling(parcel);
    if (result != nullptr) {
        // Test Marshalling as well
        MessageParcel outParcel;
        result->Marshalling(outParcel);
        delete result;
    }
}

// Test PanelStatusInfoInner Marshalling
void FuzzPanelStatusInfoInnerMarshalling(FuzzedDataProvider &provider)
{
    PanelStatusInfoInner info;
    info.panelInfo.panelType = static_cast<PanelType>(provider.ConsumeIntegralInRange<uint32_t>(0, 3));
    info.panelInfo.panelFlag = static_cast<PanelFlag>(provider.ConsumeIntegralInRange<uint32_t>(0, 3));
    info.visible = provider.ConsumeBool();
    info.trigger = static_cast<Trigger>(provider.ConsumeIntegralInRange<int32_t>(0, 2));
    info.sessionId = provider.ConsumeIntegral<uint32_t>();

    MessageParcel parcel;
    info.Marshalling(parcel);
}

// Test TextTotalConfigInner Marshalling
void FuzzTextTotalConfigInnerMarshalling(FuzzedDataProvider &provider)
{
    TextTotalConfigInner config;
    config.inputAttribute.inputPattern = provider.ConsumeIntegral<int32_t>();
    config.inputAttribute.enterKeyType = provider.ConsumeIntegral<int32_t>();
    config.cursorInfo.left = provider.ConsumeFloatingPoint<double>();
    config.cursorInfo.top = provider.ConsumeFloatingPoint<double>();
    config.textSelection.oldBegin = provider.ConsumeIntegral<int32_t>();
    config.textSelection.newEnd = provider.ConsumeIntegral<int32_t>();
    config.windowId = provider.ConsumeIntegral<uint32_t>();
    config.positionY = provider.ConsumeFloatingPoint<double>();
    config.height = provider.ConsumeFloatingPoint<double>();
    config.isSimpleKeyboardEnabled = provider.ConsumeBool();

    MessageParcel parcel;
    config.Marshalling(parcel);
}

void FuzzParcelWithRawData(FuzzedDataProvider &provider)
{
    // Test with completely raw fuzz data
    std::vector<uint8_t> rawData = provider.ConsumeBytes<uint8_t>(
        provider.ConsumeIntegralInRange<size_t>(0, 500));

    MessageParcel parcel;
    if (!rawData.empty()) {
        parcel.WriteBuffer(rawData.data(), rawData.size());
        parcel.RewindRead(0);

        // Try different unmarshalling functions with raw data
        uint8_t choice = provider.ConsumeIntegral<uint8_t>() % 5;
        switch (choice) {
            case 0: {
                TextSelectionInner *result = TextSelectionInner::Unmarshalling(parcel);
                if (result) delete result;
                break;
            }
            case 1: {
                Value *result = Value::Unmarshalling(parcel);
                if (result) delete result;
                break;
            }
            case 2: {
                CursorInfoInner *result = CursorInfoInner::Unmarshalling(parcel);
                if (result) delete result;
                break;
            }
            case 3: {
                RangeInner *result = RangeInner::Unmarshalling(parcel);
                if (result) delete result;
                break;
            }
            case 4: {
                ArrayBuffer *result = ArrayBuffer::Unmarshalling(parcel);
                if (result) delete result;
                break;
            }
            default:
                break;
        }
    }
}

} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Skip inputs that are too small
    if (size < 10) {
        return 0;
    }

    // Skip inputs that are too large to avoid timeout
    if (size > 10000) {
        return 0;
    }

    FuzzedDataProvider provider(data, size);

    // Run all fuzz test functions
    // Part 1: InputMethodEngineListener APIs
    OHOS::FuzzOnDiscardTypingText(provider);
    OHOS::FuzzOnSecurityChange(provider);
    OHOS::FuzzOnInputFinish(provider);
    OHOS::FuzzIsEnable(provider);
    OHOS::FuzzIsCallbackRegistered(provider);
    OHOS::FuzzPostTaskToEventHandler(provider);
    OHOS::FuzzOnCallingDisplayIdChanged(provider);
    OHOS::FuzzNotifyPreemption(provider);

    // Part 2: ImeEventListener APIs
    OHOS::FuzzOnImeChange(provider);
    OHOS::FuzzOnImeShow(provider);
    OHOS::FuzzOnImeHide(provider);
    OHOS::FuzzOnInputStart(provider);
    OHOS::FuzzOnInputStop(provider);

    // Part 3: OnTextChangedListener APIs
    OHOS::FuzzFinishTextPreview(provider);
    OHOS::FuzzOnDetach(provider);

    // Part 4: Combined scenarios
    OHOS::FuzzCombinedScenario(provider);

    // Part 5: Parcel Serialization/Deserialization (input_method_utils.cpp)
    OHOS::FuzzTextSelectionInnerUnmarshalling(provider);
    OHOS::FuzzTextSelectionInnerMarshalling(provider);
    OHOS::FuzzValueUnmarshalling(provider);
    OHOS::FuzzValueWithNonEmptyMap(provider);  // NEW: Cover Value's for loop
    OHOS::FuzzCursorInfoInnerUnmarshalling(provider);
    OHOS::FuzzRangeInnerUnmarshalling(provider);
    OHOS::FuzzArrayBufferUnmarshalling(provider);
    OHOS::FuzzPanelStatusInfoInnerUnmarshalling(provider);  // NEW
    OHOS::FuzzPanelStatusInfoInnerMarshalling(provider);    // NEW
    OHOS::FuzzTextTotalConfigInnerUnmarshalling(provider);  // NEW
    OHOS::FuzzTextTotalConfigInnerMarshalling(provider);    // NEW
    OHOS::FuzzParcelWithRawData(provider);

    return 0;
}

