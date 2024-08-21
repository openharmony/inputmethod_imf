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
};

InputMethod_InputMethodProxy *g_inputMethodProxy = nullptr;
std::mutex g_textEditorProxyMapMutex;

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
    OHOS::sptr<NativeTextChangedListener> listener = new NativeTextChangedListener(textEditor);
    if (listener == nullptr) {
        IMSA_HILOGE("new NativeTextChangedListener failed");
        return IME_ERR_NULL_POINTER;
    }

    g_inputMethodProxy = new InputMethod_InputMethodProxy({ textEditor, listener });
    if (g_inputMethodProxy == nullptr) {
        IMSA_HILOGE("new InputMethod_InputMethodProxy failed");
        listener = nullptr;
        return IME_ERR_NULL_POINTER;
    }
    return IME_ERR_OK;
}

static int32_t IsValidTextEditorProxy(InputMethod_TextEditorProxy *textEditor)
{
    if (textEditor == nullptr) {
        IMSA_HILOGE("textEditor is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->getTextConfigFunc == nullptr) {
        IMSA_HILOGE("textEditor->getTextConfigFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->insertTextFunc == nullptr) {
        IMSA_HILOGE("textEditor->insertTextFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->deleteForwardFunc == nullptr) {
        IMSA_HILOGE("textEditor->deleteForwardFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->deleteBackwardFunc == nullptr) {
        IMSA_HILOGE("textEditor->deleteBackwardFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->sendKeyboardStatusFunc == nullptr) {
        IMSA_HILOGE("textEditor->sendKeyboardStatusFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (textEditor->sendEnterKeyFunc == nullptr) {
        IMSA_HILOGE("textEditor->sendEnterKeyFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->moveCursorFunc == nullptr) {
        IMSA_HILOGE("textEditor->moveCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->handleSetSelectionFunc == nullptr) {
        IMSA_HILOGE("textEditor->handleSetSelectionFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->handleExtendActionFunc == nullptr) {
        IMSA_HILOGE("textEditor->handleExtendActionFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->getLeftTextOfCursorFunc == nullptr) {
        IMSA_HILOGE("textEditor->getLeftTextOfCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->getRightTextOfCursorFunc == nullptr) {
        IMSA_HILOGE("textEditor->getRightTextOfCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (textEditor->getTextIndexAtCursorFunc == nullptr) {
        IMSA_HILOGE("textEditor->getTextIndexAtCursorFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (textEditor->receivePrivateCommandFunc == nullptr) {
        IMSA_HILOGE("textEditor->receivePrivateCommandFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    if (textEditor->setPreviewTextFunc == nullptr) {
        IMSA_HILOGE("textEditor->setPreviewTextFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    if (textEditor->finishTextPreviewFunc == nullptr) {
        IMSA_HILOGE("textEditor->finishTextPreviewFunc is nullptr");
        return IME_ERR_NULL_POINTER;
    }

    return IME_ERR_OK;
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

    TextConfig textConfig = {
        .inputAttribute = {
            .inputPattern = static_cast<InputMethod_TextInputType>(config.inputType),
            .enterKeyType = static_cast<InputMethod_EnterKeyType>(config.enterKeyType),
            .isTextPreviewSupported = config.previewTextSupported,
        },
        .cursorInfo = {
            .left = config.cursorInfo.left,
            .top = config.cursorInfo.top,
            .width = config.cursorInfo.width,
            .height = config.cursorInfo.height,
        },
        .range = {
            .start = config.selectionStart,
            .end = config.selectionEnd,
        },
        .windowId = config.windowId,
        .positionY = config.avoidInfo.positionY,
        .height = config.avoidInfo.height,
    };

    auto controller = InputMethodController::GetInstance();
    OHOS::sptr<NativeTextChangedListener> listener = nullptr;
    {
        std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
        listener = g_inputMethodProxy->listener;
    }

    int32_t err = controller->Attach(listener, options->showKeyboard, textConfig);
    if (err == ErrorCode::NO_ERROR) {
        errCode = IME_ERR_OK;
        std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
        *inputMethodProxy = g_inputMethodProxy;
    } else {
        errCode = ErrorCodeConvert(err);
    }

    return errCode;
}

InputMethod_ErrorCode OH_InputMethodController_Detach(InputMethod_InputMethodProxy *inputMethodProxy)
{
    if (inputMethodProxy == nullptr) {
        IMSA_HILOGE("inputMethodProxy is nullptr");
        return IME_ERR_NULL_POINTER;
    }
    {
        std::lock_guard<std::mutex> guard(g_textEditorProxyMapMutex);
        if (g_inputMethodProxy != nullptr && inputMethodProxy == g_inputMethodProxy) {
            g_inputMethodProxy->listener = nullptr;
            delete g_inputMethodProxy;
            g_inputMethodProxy = nullptr;
        }
    }
    return ErrorCodeConvert(InputMethodController::GetInstance()->Close());
}
#ifdef __cplusplus
}
#endif /* __cplusplus */