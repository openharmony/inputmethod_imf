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
#include <event_handler.h>
#include <gtest/gtest.h>
#include <string_ex.h>
#include <sys/time.h>

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ability_manager_client.h"
#include "accesstoken_kit.h"
#include "global.h"
#include "i_input_method_agent.h"
#include "i_input_method_system_ability.h"
#include "input_client_stub.h"
#include "input_data_channel_stub.h"
#include "input_method_ability.h"
#include "input_method_controller.h"
#include "input_method_engine_listener.h"
#include "input_method_system_ability_proxy.h"
#include "input_method_utils.h"
#include "iservice_registry.h"
#include "keyboard_listener.h"
#include "message_parcel.h"
#include "nativetoken_kit.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

using namespace testing::ext;
using namespace OHOS::Security::AccessToken;
using namespace OHOS::AccountSA;
namespace OHOS {
namespace MiscServices {
constexpr int32_t MAIN_USER_ID = 100;
void InitTestConfiguration()
{
    std::string bundleName = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility().GetBundleName();
    IMSA_HILOGI("bundleName: %{public}s", bundleName.c_str());
    std::vector<int32_t> userIds;
    auto ret = OsAccountManager::QueryActiveOsAccountIds(userIds);
    if (ret != ErrorCode::NO_ERROR || userIds.empty()) {
        IMSA_HILOGE("query active os account id failed");
        userIds[0] = MAIN_USER_ID;
    }
    HapInfoParams infoParams = {
        .userID = userIds[0], .bundleName = bundleName, .instIndex = 0, .appIDDesc = "ohos.inputmethod_test.demo"
    };
    PermissionStateFull permissionState = { .permissionName = "ohos.permission.CONNECT_IME_ABILITY",
        .isGeneral = true,
        .resDeviceID = { "local" },
        .grantStatus = { PermissionState::PERMISSION_GRANTED },
        .grantFlags = { 1 } };
    HapPolicyParams policyParams = {
        .apl = APL_NORMAL, .domain = "test.domain.inputmethod", .permList = {}, .permStateList = { permissionState }
    };

    AccessTokenKit::AllocHapToken(infoParams, policyParams);
    auto tokenID = AccessTokenKit::GetHapTokenID(infoParams.userID, infoParams.bundleName, infoParams.instIndex);
    int res = SetSelfTokenID(tokenID);
    if (res == ErrorCode::NO_ERROR) {
        IMSA_HILOGI("SetSelfTokenID success!");
    } else {
        IMSA_HILOGE("SetSelfTokenID fail!");
    }
}

class TextListener : public OnTextChangedListener {
public:
    TextListener()
    {
        std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create("TextListenerNotifier");
        serviceHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    ~TextListener()
    {
    }
    static KeyboardInfo keyboardInfo_;
    static std::mutex cvMutex_;
    static std::condition_variable cv_;
    std::shared_ptr<AppExecFwk::EventHandler> serviceHandler_;
    static bool WaitIMACallback()
    {
        std::unique_lock<std::mutex> lock(TextListener::cvMutex_);
        return TextListener::cv_.wait_for(lock, std::chrono::seconds(1)) != std::cv_status::timeout;
    }
    void InsertText(const std::u16string &text)
    {
        IMSA_HILOGI("IMC TEST TextListener InsertText: %{public}s", Str16ToStr8(text).c_str());
    }

    void DeleteBackward(int32_t length)
    {
        IMSA_HILOGI("IMC TEST TextListener DeleteBackward length: %{public}d", length);
    }

    void SetKeyboardStatus(bool status)
    {
        IMSA_HILOGI("IMC TEST TextListener SetKeyboardStatus %{public}d", status);
    }
    void DeleteForward(int32_t length)
    {
        IMSA_HILOGI("IMC TEST TextListener DeleteForward length: %{public}d", length);
    }
    void SendKeyEventFromInputMethod(const KeyEvent &event)
    {
        IMSA_HILOGI("IMC TEST TextListener sendKeyEventFromInputMethod");
    }
    void SendKeyboardInfo(const KeyboardInfo &status)
    {
        IMSA_HILOGD("TextListener::SendKeyboardInfo %{public}d", status.GetKeyboardStatus());
        constexpr int32_t interval = 20;
        {
            std::unique_lock<std::mutex> lock(cvMutex_);
            IMSA_HILOGD("TextListener::SendKeyboardInfo lock");
            keyboardInfo_ = status;
        }
        serviceHandler_->PostTask([this]() { cv_.notify_all(); }, interval);
        IMSA_HILOGD("TextListener::SendKeyboardInfo notify_all");
    }
    void MoveCursor(const Direction direction)
    {
        IMSA_HILOGI("IMC TEST TextListener MoveCursor");
    }
    void HandleSetSelection(int32_t start, int32_t end)
    {
    }
    void HandleExtendAction(int32_t action)
    {
    }
    void HandleSelect(int32_t keyCode, int32_t cursorMoveSkip)
    {
    }
};
KeyboardInfo TextListener::keyboardInfo_;
std::mutex TextListener::cvMutex_;
std::condition_variable TextListener::cv_;

class KeyboardListenerImpl : public KeyboardListener {
public:
    KeyboardListenerImpl(){};
    ~KeyboardListenerImpl(){};
    static int32_t keyCode_;
    static int32_t keyStatus_;
    static CursorInfo cursorInfo_;
    bool OnKeyEvent(int32_t keyCode, int32_t keyStatus) override;
    void OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height) override;
    void OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd) override;
    void OnTextChange(const std::string &text) override;
};
int32_t KeyboardListenerImpl::keyCode_ = 0;
int32_t KeyboardListenerImpl::keyStatus_ = 0;
CursorInfo KeyboardListenerImpl::cursorInfo_ = {};
bool KeyboardListenerImpl::OnKeyEvent(int32_t keyCode, int32_t keyStatus)
{
    IMSA_HILOGD("KeyboardListenerImpl::OnKeyEvent %{public}d %{public}d", keyCode, keyStatus);
    keyCode_ = keyCode;
    keyStatus_ = keyStatus;
    return true;
}
void KeyboardListenerImpl::OnCursorUpdate(int32_t positionX, int32_t positionY, int32_t height)
{
    IMSA_HILOGD("KeyboardListenerImpl::OnCursorUpdate %{public}d %{public}d %{public}d", positionX, positionY, height);
    cursorInfo_ = { static_cast<double>(positionX), static_cast<double>(positionY), 0, static_cast<double>(height) };
}
void KeyboardListenerImpl::OnSelectionChange(int32_t oldBegin, int32_t oldEnd, int32_t newBegin, int32_t newEnd)
{
}
void KeyboardListenerImpl::OnTextChange(const std::string &text)
{
}

class InputMethodEngineListenerImpl : public InputMethodEngineListener {
public:
    InputMethodEngineListenerImpl(){};
    ~InputMethodEngineListenerImpl(){};
    static bool keyboardState_;
    static bool isInputStart_;
    static uint32_t windowId_;
    void OnKeyboardStatus(bool isShow) override;
    void OnInputStart() override;
    void OnInputStop(const std::string &imeId) override;
    void OnSetCallingWindow(uint32_t windowId) override;
    void OnSetSubtype(const SubProperty &property) override;
};
bool InputMethodEngineListenerImpl::keyboardState_ = false;
bool InputMethodEngineListenerImpl::isInputStart_ = false;
uint32_t InputMethodEngineListenerImpl::windowId_ = 0;

void InputMethodEngineListenerImpl::OnKeyboardStatus(bool isShow)
{
    keyboardState_ = isShow;
}
void InputMethodEngineListenerImpl::OnInputStart()
{
    isInputStart_ = true;
}
void InputMethodEngineListenerImpl::OnInputStop(const std::string &imeId)
{
    isInputStart_ = false;
}
void InputMethodEngineListenerImpl::OnSetCallingWindow(uint32_t windowId)
{
    windowId_ = windowId;
}
void InputMethodEngineListenerImpl::OnSetSubtype(const SubProperty &property)
{
    IMSA_HILOGD("InputMethodEngineListenerImpl::OnSetSubtype");
}

class InputMethodEditorTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static sptr<InputMethodController> inputMethodController_;
    static sptr<InputMethodAbility> inputMethodAbility_;
    static std::shared_ptr<MMI::KeyEvent> keyEvent_;
    static std::shared_ptr<KeyboardListenerImpl> kbListener_;
    static std::shared_ptr<InputMethodEngineListenerImpl> imeListener_;
    static sptr<OnTextChangedListener> textListener_;
};
sptr<InputMethodController> InputMethodEditorTest::inputMethodController_;
sptr<InputMethodAbility> InputMethodEditorTest::inputMethodAbility_;
std::shared_ptr<MMI::KeyEvent> InputMethodEditorTest::keyEvent_;
std::shared_ptr<KeyboardListenerImpl> InputMethodEditorTest::kbListener_;
std::shared_ptr<InputMethodEngineListenerImpl> InputMethodEditorTest::imeListener_;
sptr<OnTextChangedListener> InputMethodEditorTest::textListener_;

void InputMethodEditorTest::SetUpTestCase(void)
{
    IMSA_HILOGI("InputMethodEditorTest::SetUpTestCase");
    inputMethodAbility_ = InputMethodAbility::GetInstance();
    inputMethodAbility_->OnImeReady();
    kbListener_ = std::make_shared<KeyboardListenerImpl>();
    imeListener_ = std::make_shared<InputMethodEngineListenerImpl>();
    textListener_ = new TextListener();
    inputMethodAbility_->SetKdListener(kbListener_);
    inputMethodAbility_->SetImeListener(imeListener_);
    inputMethodController_ = InputMethodController::GetInstance();

    keyEvent_ = MMI::KeyEvent::Create();
    constexpr int32_t keyAction = 2;
    constexpr int32_t keyCode = 2001;
    keyEvent_->SetKeyAction(keyAction);
    keyEvent_->SetKeyCode(keyCode);
}

void InputMethodEditorTest::TearDownTestCase(void)
{
    IMSA_HILOGI("InputMethodEditorTest::TearDownTestCase");
}

void InputMethodEditorTest::SetUp(void)
{
    IMSA_HILOGI("InputMethodEditorTest::SetUp");
}

void InputMethodEditorTest::TearDown(void)
{
    IMSA_HILOGI("InputMethodEditorTest::TearDown");
}

/**
 * @tc.name: testIMCAttachUnfocused
 * @tc.desc: InputMethodEditorTest Attach.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testIMCAttachUnfocused, TestSize.Level0)
{
    IMSA_HILOGD("InputMethodEditorTest Attach Unfocused Test START");
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(textListener_, false);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
    ret = InputMethodEditorTest::inputMethodController_->Attach(textListener_);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
    ret = InputMethodEditorTest::inputMethodController_->Attach(textListener_, true);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
}

/**
 * @tc.name: test Unfocused
 * @tc.desc: InputMethodEditorTest ShowTextInput Unfocused
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testShowTextInputUnfocused, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest Unfocused Test START");
    int32_t ret = InputMethodEditorTest::inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    std::u16string text = Str8ToStr16("");
    ret = InputMethodEditorTest::inputMethodController_->GetTextBeforeCursor(1, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->GetTextAfterCursor(1, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    int32_t tempVar = -1;
    ret = InputMethodEditorTest::inputMethodController_->GetTextIndexAtCursor(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    bool result = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(InputMethodEditorTest::keyEvent_);
    EXPECT_FALSE(result);
    ret = InputMethodEditorTest::inputMethodController_->GetEnterKeyType(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->GetInputPattern(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->StopInputSession();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_FOCUSED);
    ret = InputMethodEditorTest::inputMethodController_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
}

/**
 * @tc.name: test AttachFocused
 * @tc.desc: InputMethodEditorTest Attach Focused
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testAttachFocused, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest Attach Focused Test START");
    InitTestConfiguration();
    InputMethodEditorTest::imeListener_->isInputStart_ = false;
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    InputMethodEditorTest::imeListener_->isInputStart_ = false;
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_);
    EXPECT_TRUE(TextListener::WaitIMACallback());
    EXPECT_TRUE(imeListener_->isInputStart_ && imeListener_->keyboardState_);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    InputMethodEditorTest::imeListener_->isInputStart_ = false;
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_TRUE(TextListener::WaitIMACallback());
    EXPECT_TRUE(imeListener_->isInputStart_ && imeListener_->keyboardState_);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testShowSoftKeyboard
 * @tc.desc: InputMethodEditorTest ShowSoftKeyboard
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testShowSoftKeyboard, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest ShowSoftKeyboard Test START");
    InputMethodEditorTest::inputMethodController_->Close();
    InitTestConfiguration();
    InputMethodEditorTest::imeListener_->keyboardState_ = false;
    TextListener::keyboardInfo_.SetKeyboardStatus(static_cast<int32_t>(KeyboardStatus::NONE));
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, false);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_TRUE(TextListener::WaitIMACallback());
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_TRUE(
        imeListener_->keyboardState_ && TextListener::keyboardInfo_.GetKeyboardStatus() == KeyboardStatus::SHOW);
}

/**
 * @tc.name: testIMCHideTextInput.
 * @tc.desc: InputMethodEditorTest testHideTextInput.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testIMCHideTextInput, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest HideTextInputAndShowTextInput Test START");
    InputMethodEditorTest::inputMethodController_->Close();
    InitTestConfiguration();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);

    imeListener_->keyboardState_ = true;
    TextListener::keyboardInfo_.SetKeyboardStatus(static_cast<int32_t>(KeyboardStatus::NONE));
    InputMethodEditorTest::inputMethodController_->HideTextInput();
    bool result = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(InputMethodEditorTest::keyEvent_);
    EXPECT_FALSE(result);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    std::u16string text = Str8ToStr16("");
    ret = InputMethodEditorTest::inputMethodController_->GetTextBeforeCursor(1, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->GetTextAfterCursor(1, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    int32_t tempVar = -1;
    ret = InputMethodEditorTest::inputMethodController_->GetTextIndexAtCursor(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->GetEnterKeyType(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->GetInputPattern(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
}

/**
 * @tc.name: testShowTextInput
 * @tc.desc: InputMethodEditorTest ShowTextInput
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testShowTextInput, TestSize.Level0)
{
    IMSA_HILOGI("InputMethodEditorTest ShowTextInput Test START");
    InputMethodEditorTest::inputMethodController_->Close();
    InitTestConfiguration();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    InputMethodEditorTest::inputMethodController_->HideTextInput();

    ret = InputMethodEditorTest::inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    bool result = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(InputMethodEditorTest::keyEvent_);
    usleep(300);
    ret = ret && kbListener_->keyCode_ == keyEvent_->GetKeyCode()
          && kbListener_->keyStatus_ == keyEvent_->GetKeyAction();
    EXPECT_TRUE(result);
}

/**
 * @tc.name: testIMCClose.
 * @tc.desc: InputMethodEditorTest Close.
 * @tc.type: FUNC
 */
HWTEST_F(InputMethodEditorTest, testIMCClose, TestSize.Level0)
{
    IMSA_HILOGI("IMC Close Test START");
    InitTestConfiguration();
    int32_t ret = InputMethodEditorTest::inputMethodController_->Attach(InputMethodEditorTest::textListener_, true);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    InputMethodEditorTest::inputMethodController_->Close();

    ret = InputMethodEditorTest::inputMethodController_->ShowTextInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_BOUND);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    std::u16string text = Str8ToStr16("");
    ret = InputMethodEditorTest::inputMethodController_->GetTextBeforeCursor(1, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->GetTextAfterCursor(1, text);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    int32_t tempVar = -1;
    ret = InputMethodEditorTest::inputMethodController_->GetTextIndexAtCursor(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    bool result = InputMethodEditorTest::inputMethodController_->DispatchKeyEvent(InputMethodEditorTest::keyEvent_);
    EXPECT_FALSE(result);
    ret = InputMethodEditorTest::inputMethodController_->GetEnterKeyType(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->GetInputPattern(tempVar);
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideSoftKeyboard();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->ShowCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
    ret = InputMethodEditorTest::inputMethodController_->HideCurrentInput();
    EXPECT_EQ(ret, ErrorCode::ERROR_CLIENT_NOT_EDITABLE);
}
} // namespace MiscServices
} // namespace OHOS