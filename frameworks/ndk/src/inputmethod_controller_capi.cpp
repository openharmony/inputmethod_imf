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
#include <map>
#include <mutex>

#include "global.h"
#include "input_method_controller.h"
#include "input_method_utils.h"
#include "inputmethod_controller_capi.h"
#include "native_inputmethod_types.h"
#include "native_inputmethod_utils.h"
#include "native_text_changed_listener.h"
using namespace OHOS::MiscServices;
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct InputMethod_InputMethodProxy {
    InputMethod_TextEditorProxy *textEditor = nullptr;
    OHOS::sptr<NativeTextChangedListener> listener = nullptr;
    bool attached = false;
};

InputMethod_InputMethodProxy *g_inputMethodProxy = nullptr;
std::mutex g_textEditorProxyMapMutex;

InputMethod_ErrorCode IsValidInputMethodProxy(const InputMethod_InputMethodProxy *inputMethodProxy)
{
    if (inputMethodProxy == nullptr) {
        IMSA_HILOGE("inputMethodProxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
    if (g_inputMethodProxy == nullptr) {
        IMSA_HILOGE("g_inputMethodProxy is nullptr");
        return IME_ERR_DETACHED;
    }

    if (g_inputMethodProxy != inputMethodProxy) {
        IMSA_HILOGE("g_inputMethodProxy is not equal to inputMethodProxy");
        return IME_ERR_PARAMCHECK;
    }

    if (!(g_inputMethodProxy->attached)) {
        IMSA_HILOGE("g_inputMethodProxy is not attached");
        return IME_ERR_DETACHED;
    }

    return IME_ERR_OK;
}
static InputMethod_ErrorCode GetInputMethodProxy(InputMethod_TextEditorProxy *textEditor)
{
    std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
    if (g_inputMethodProxy != nullptr && textEditor == g_inputMethodProxy->textEditor) {
        return IME_ERR_OK;
    }

    if (g_inputMethodProxy != nullptr && textEditor != g_inputMethodProxy->textEditor) {
        g_inputMethodProxy->listener = nullptr;
        delete g_inputMethodProxy;
        g_inputMethodProxy = nullptr;
    }
    OHOS::sptr<NativeTextChangedListener> listener = new (std::nothrow) NativeTextChangedListener(textEditor);
    if (listener == nullptr) {
        IMSA_HILOGE("new NativeTextChangedListener failed");
        return IME_ERR_NULL_POINTER;
    }

    g_inputMethodProxy = new (std::nothrow) InputMethod_InputMethodProxy({ textEditor, listener });
    if (g_inputMethodProxy == nullptr) {
        IMSA_HILOGE("new InputMethod_InputMethodProxy failed");
        listener = nullptr;
        return IME_ERR_NULL_POINTER;
    }
    return IME_ERR_OK;
}
#define CHECK_MEMBER_NULL(textEditor, member)   \
    do {                                        \
        if ((textEditor)->member == nullptr) {  \
            IMSA_HILOGE(#member " is nullptr"); \
            return IME_ERR_NULL_POINTER;        \
        }                                       \
    } while (0)
static int32_t IsValidTextEditorProxy(InputMethod_TextEditorProxy *textEditor)
{
    if (textEditor == nullptr) {
        IMSA_HILOGE("textEditor is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    CHECK_MEMBER_NULL(textEditor, getTextConfigFunc);
    CHECK_MEMBER_NULL(textEditor, insertTextFunc);
    CHECK_MEMBER_NULL(textEditor, deleteForwardFunc);
    CHECK_MEMBER_NULL(textEditor, deleteBackwardFunc);
    CHECK_MEMBER_NULL(textEditor, sendKeyboardStatusFunc);
    CHECK_MEMBER_NULL(textEditor, sendEnterKeyFunc);
    CHECK_MEMBER_NULL(textEditor, moveCursorFunc);
    CHECK_MEMBER_NULL(textEditor, handleSetSelectionFunc);
    CHECK_MEMBER_NULL(textEditor, handleExtendActionFunc);
    CHECK_MEMBER_NULL(textEditor, getLeftTextOfCursorFunc);
    CHECK_MEMBER_NULL(textEditor, getRightTextOfCursorFunc);
    CHECK_MEMBER_NULL(textEditor, getTextIndexAtCursorFunc);
    CHECK_MEMBER_NULL(textEditor, receivePrivateCommandFunc);
    CHECK_MEMBER_NULL(textEditor, setPreviewTextFunc);
    CHECK_MEMBER_NULL(textEditor, finishTextPreviewFunc);
    return IME_ERR_OK;
}

static TextConfig ConstructTextConfig(const InputMethod_TextConfig &config)
{
    TextConfig textConfig;
    textConfig.inputAttribute.inputPattern = static_cast<InputMethod_TextInputType>(config.inputType);
    textConfig.inputAttribute.enterKeyType = static_cast<InputMethod_EnterKeyType>(config.enterKeyType);
    textConfig.inputAttribute.isTextPreviewSupported = config.previewTextSupported;
    textConfig.cursorInfo.left = config.cursorInfo.left;
    textConfig.cursorInfo.top = config.cursorInfo.top;
    textConfig.cursorInfo.width = config.cursorInfo.width;
    textConfig.cursorInfo.height = config.cursorInfo.height;
    textConfig.range.start = config.selectionStart;
    textConfig.range.end = config.selectionEnd;
    textConfig.windowId = config.windowId;
    textConfig.positionY = config.avoidInfo.positionY;
    textConfig.height = config.avoidInfo.height;
    auto placeholderLength = config.placeholderLength;
    if (placeholderLength >0 &&  config.placeholder[placeholderLength - 1] == UTF16_ENDING_SYMBOL) {
        placeholderLength = placeholderLength -1;
    }
    auto abilityNameLength = config.abilityNameLength;
    if (abilityNameLength >0 && config.abilityName[abilityNameLength - 1] == UTF16_ENDING_SYMBOL) {
        abilityNameLength = abilityNameLength - 1;
    }
    textConfig.inputAttribute.placeholder = std::u16string(config.placeholder, placeholderLength);
    textConfig.inputAttribute.abilityName =  std::u16string(config.abilityName, abilityNameLength);
    return textConfig;
}

InputMethod_ErrorCode OH_InputMethodController_Attach(InputMethod_TextEditorProxy *textEditor,
    InputMethod_AttachOptions *options, InputMethod_InputMethodProxy **inputMethodProxy)
{
    if ((IsValidTextEditorProxy(textEditor) != IME_ERR_OK) || options == nullptr || inputMethodProxy == nullptr) {
        IMSA_HILOGE("invalid parameter");
        return IME_ERR_NULL_POINTER;
    }

    InputMethod_ErrorCode errCode = GetInputMethodProxy(textEditor);
    if (errCode != IME_ERR_OK) {
        return errCode;
    }

    InputMethod_TextConfig config;
    textEditor->getTextConfigFunc(textEditor, &config);

    auto textConfig = ConstructTextConfig(config);

    auto controller = InputMethodController::GetInstance();
    if (controller == nullptr) {
        IMSA_HILOGE("controller is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    OHOS::sptr<NativeTextChangedListener> listener = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
        if (g_inputMethodProxy != nullptr) {
            listener = g_inputMethodProxy->listener;
        }
    }
    AttachOptions attachOptions;
    attachOptions.isShowKeyboard = options->showKeyboard;
    attachOptions.requestKeyboardReason =
        static_cast<RequestKeyboardReason>(static_cast<int32_t>(options->requestKeyboardReason));
    int32_t err = controller->Attach(listener, attachOptions, textConfig, ClientType::CAPI);
    if (err == ErrorCode::NO_ERROR) {
        errCode = IME_ERR_OK;
        std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
        if (g_inputMethodProxy != nullptr) {
            g_inputMethodProxy->attached = true;
        }
        *inputMethodProxy = g_inputMethodProxy;
    } else {
        errCode = ErrorCodeConvert(err);
    }

    return errCode;
}

void ClearInputMethodProxy(void)
{
    std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
    if (g_inputMethodProxy != nullptr) {
        IMSA_HILOGI("g_inputMethodProxy is detached");
        g_inputMethodProxy->attached = false;
    }
}

InputMethod_ErrorCode OH_InputMethodController_Detach(InputMethod_InputMethodProxy *inputMethodProxy)
{
    if (inputMethodProxy == nullptr) {
        IMSA_HILOGE("inputMethodProxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    {
        std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
        if (g_inputMethodProxy == nullptr) {
            IMSA_HILOGE("g_inputMethodProxy is nullptr");
            return IME_ERR_DETACHED;
        }

        if (g_inputMethodProxy != inputMethodProxy) {
            IMSA_HILOGE("g_inputMethodProxy is not equal to inputMethodProxy");
            return IME_ERR_PARAMCHECK;
        }

        IMSA_HILOGI("detach g_inputMethodProxy");
        g_inputMethodProxy->listener = nullptr;
        delete g_inputMethodProxy;
        g_inputMethodProxy = nullptr;
    }
    auto instance  = InputMethodController::GetInstance();
    if (instance == nullptr) {
        IMSA_HILOGE("instance is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    return ErrorCodeConvert(instance->Close());
}
#ifdef __cplusplus
}
#endif /* __cplusplus */