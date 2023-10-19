/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_CONTROLLER_H
#define FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_CONTROLLER_H

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include "controller_listener.h"
#include "event_handler.h"
#include "event_status_manager.h"
#include "global.h"
#include "i_input_method_agent.h"
#include "i_input_method_system_ability.h"
#include "input_client_info.h"
#include "input_method_property.h"
#include "input_method_setting_listener.h"
#include "input_method_status.h"
#include "input_method_utils.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "key_event.h"
#include "message_handler.h"
#include "visibility.h"

namespace OHOS {
namespace MiscServices {
class OnTextChangedListener : public virtual RefBase {
public:
    virtual void InsertText(const std::u16string &text) = 0;
    virtual void DeleteForward(int32_t length) = 0;
    virtual void DeleteBackward(int32_t length) = 0;
    virtual void SendKeyEventFromInputMethod(const KeyEvent &event) = 0;
    virtual void SendKeyboardStatus(const KeyboardStatus &keyboardStatus) = 0;
    virtual void SendFunctionKey(const FunctionKey &functionKey) = 0;
    virtual void SetKeyboardStatus(bool status) = 0;
    virtual void MoveCursor(const Direction direction) = 0;
    virtual void HandleSetSelection(int32_t start, int32_t end) = 0;
    virtual void HandleExtendAction(int32_t action) = 0;
    virtual void HandleSelect(int32_t keyCode, int32_t cursorMoveSkip) = 0;
    virtual std::u16string GetLeftTextOfCursor(int32_t number) = 0;
    virtual std::u16string GetRightTextOfCursor(int32_t number) = 0;
    virtual int32_t GetTextIndexAtCursor() = 0;
};

class InputMethodController : public RefBase {
public:
    /**
     * @brief Get the instance of InputMethodController.
     *
     * This function is used to get the instance of InputMethodController.
     *
     * @return The instance of InputMethodController.
     * @since 6
     */
    IMF_API static sptr<InputMethodController> GetInstance();

    /**
     * @brief Show soft keyboard, set listener and bind IMSA with default states and attribute.
     *
     * This function is used to show soft keyboard,  set listener and bind IMSA,
     * default state is 'true', default attribute is 'InputAttribute::PATTERN_TEXT'.
     *
     * @param listener Indicates the listener in order to manipulate text.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t Attach(sptr<OnTextChangedListener> &listener);

    /**
     * @brief Set listener and bind IMSA with given states and default attribute.
     *
     * This function is used to set listener and bind IMSA,
     * default attribute is 'InputAttribute::PATTERN_TEXT'. Show soft keyboard when state is true.
     *
     * @param listener          Indicates the listener in order to manipulate text.
     * @param isShowKeyboard    Indicates the state, if you want to show soft keyboard, please pass in true.
     * @return Returns 0 for success, others for failure.
     * @since 8
     */
    IMF_API int32_t Attach(sptr<OnTextChangedListener> &listener, bool isShowKeyboard);

    /**
     * @brief Set listener and bind IMSA with given states and attribute.
     *
     * This function is used to set listener and bind IMSA.
     * Show soft keyboard when state is true, and customized attribute.
     *
     * @param listener          Indicates the listener in order to manipulate text.
     * @param isShowKeyboard    Indicates the state, if you want to show soft keyboard, please pass in true.
     * @param attribute         Indicates the attribute, such as input pattern, enter eyType, input option.
     * @return Returns 0 for success, others for failure.
     * @since 8
     */
    IMF_API int32_t Attach(sptr<OnTextChangedListener> &listener, bool isShowKeyboard, const InputAttribute &attribute);

    /**
     * @brief Set listener and bind IMSA with given states and textConfig.
     *
     * This function is used to set listener and bind IMSA.
     * Show soft keyboard when state is true, and customized attribute.
     *
     * @param listener          Indicates the listener in order to manipulate text.
     * @param isShowKeyboard    Indicates the state, if you want to show soft keyboard, please pass in true.
     * @param textConfig        Indicates the textConfig, such as input attribute, cursorInfo, range of text selection,
     *                          windowId.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t Attach(sptr<OnTextChangedListener> &listener, bool isShowKeyboard, const TextConfig &textConfig);

    /**
     * @brief Show soft keyboard.
     *
     * This function is used to show soft keyboard of current client.
     *
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t ShowTextInput();

    /**
     * @brief Hide soft keyboard.
     *
     * This function is used to hide soft keyboard of current client, and keep binding.
     *
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t HideTextInput();

    /**
     * @brief Hide current input method, clear text listener and unbind IMSA.
     *
     * This function is used to stop input, whick will set listener to nullptr,
     * hide current soft keyboard and unbind IMSA.
     *
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t Close();

    /**
     * @brief A callback function when the cursor changes.
     *
     * This function is the callback when the cursor changes.
     *
     * @param cursorInfo Indicates the information of current cursor changes.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t OnCursorUpdate(CursorInfo cursorInfo);

    /**
     * @brief A callback function when the cursor changes.
     *
     * This function is the callback when the cursor changes.
     *
     * @param text  Indicates the currently selected text.
     * @param start Indicates the coordinates of the current start.
     * @param end   Indicates the coordinates of the current end.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t OnSelectionChange(std::u16string text, int start, int end);

    /**
     * @brief Changing the configuration of soft keyboard.
     *
     * This function is used to change the configuration of soft keyboard.
     *
     * @param info Indicates the current configuration.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t OnConfigurationChange(Configuration info);

    /**
     * @brief Set InputMethodSettingListener listener.
     *
     * This function is used to set InputMethodSettingListener  listener to facilitate listening input method changes.
     *
     * @param listener Indicates the listener to be set.
     * @since 6
     */
    IMF_API void SetSettingListener(std::shared_ptr<InputMethodSettingListener> listener);
    IMF_API int32_t UpdateListenEventFlag(const std::string &type, bool isOn);
    IMF_API void SetControllerListener(std::shared_ptr<ControllerListener> controllerListener);

    /**
     * @brief Dispatch keyboard event.
     *
     * This function is used to Dispatch events of keyboard.
     *
     * @param keyEvent Indicates the events keyboard.
     * @return Returns true for success otherwise for failure.
     * @since 6
     */
    IMF_API bool DispatchKeyEvent(std::shared_ptr<MMI::KeyEvent> keyEvent);

    /**
     * @brief List input methods.
     *
     * This function is used to list all of input methods.
     *
     * @param props Indicates the input methods that will be listed.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t ListInputMethod(std::vector<Property> &props);

    /**
     * @brief List input methods.
     *
     * This function is used to list enabled or disabled input methods.
     *
     * @param props     Indicates the input methods that will be listed.
     * @param enable    Indicates the state of input method.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t ListInputMethod(bool enable, std::vector<Property> &props);

    /**
     * @brief List input method subtypes.
     *
     * This function is used to list specified input method subtypes.
     *
     * @param property      Indicates the specified input method property.
     * @param subProperties Indicates the subtypes of specified input method that will be listed.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t ListInputMethodSubtype(const Property &property, std::vector<SubProperty> &subProperties);

    /**
     * @brief List current input method subtypes.
     *
     * This function is used to list current input method subtypes.
     *
     * @param subProperties Indicates the subtypes of current input method that will be listed.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t ListCurrentInputMethodSubtype(std::vector<SubProperty> &subProperties);

    /**
     * @brief Get enter key type.
     *
     * This function is used to get enter key type of current client.
     *
     * @param keyType Indicates the enter key type of current client that will be obtained, such as SEND, SEARCH...
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t GetEnterKeyType(int32_t &keyType);

    /**
     * @brief Get input pattern.
     *
     * This function is used to get text input type of current client.
     *
     * @param inputPattern Indicates the text input type of current client that will be obtained, such as TEXT, URL...
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t GetInputPattern(int32_t &inputPattern);

    /**
     * @brief Get text config.
     *
     * This function is used to get text config of current client.
     *
     * @param textConfig Indicates the text config of current client that will be obtained.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t GetTextConfig(TextTotalConfig &config);

    /**
     * @brief Get current input method property.
     *
     * This function is used to get current input method property.
     *
     * @return The property of current input method.
     * @since 6
     */
    IMF_API std::shared_ptr<Property> GetCurrentInputMethod();

    /**
     * @brief Get current input method subtypes.
     *
     * This function is used to get current input method's current subtype.
     *
     * @return The subtypes of current input method.
     * @since 6
     */
    IMF_API std::shared_ptr<SubProperty> GetCurrentInputMethodSubtype();

    /**
     * @brief Set calling window id.
     *
     * This function is used to set calling window id to input method.
     *
     * @param windowId Indicates the window id.
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t SetCallingWindow(uint32_t windowId);

    /**
     * @brief Switch input method or subtype.
     *
     * This function is used to switch input method or subtype.
     *
     * @param name      Indicates the id of target input method.
     * @param subName   Optional parameter. Indicates the subtype of target input method.
     * @return Returns 0 for success, others for failure.
     * @since 8
     */
    IMF_API int32_t SwitchInputMethod(const std::string &name, const std::string &subName = "");

    /**
     * @brief Show soft keyboard.
     *
     * This function is used to show soft keyboard of current client.
     *
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t ShowSoftKeyboard();

    /**
     * @brief Hide soft keyboard.
     *
     * This function is used to hide soft keyboard of current client, and keep binding.
     *
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t HideSoftKeyboard();

    /**
     * @brief Stop current input session.
     *
     * This function is used to stop current input session.
     *
     * @return Returns 0 for success, others for failure.
     * @since 6
     */
    IMF_API int32_t StopInputSession();

    /**
     * @brief Show input method setting extension dialog.
     *
     * This function is used to show input method setting extension dialog.
     *
     * @return Returns 0 for success, others for failure.
     * @since 8
     */
    IMF_API int32_t ShowOptionalInputMethod();

    // Deprecated innerkits with no permission check, kept for compatibility

    /**
     * @brief Show soft keyboard.
     *
     * This function is used to show soft keyboard of current client.
     *
     * @return Returns 0 for success, others for failure.
     * @deprecated since 9
     * @since 6
     */
    IMF_API int32_t ShowCurrentInput();

    /**
     * @brief Hide soft keyboard.
     *
     * This function is used to hide soft keyboard of current client, and keep binding.
     *
     * @return Returns 0 for success, others for failure.
     * @deprecated since 9
     * @since 6
     */
    IMF_API int32_t HideCurrentInput();

    /**
     * @brief Show input method setting extension dialog.
     *
     * This function is used to show input method setting extension dialog.
     *
     * @return Returns 0 for success, others for failure.
     * @deprecated since 9
     * @since 6
     */
    IMF_API int32_t DisplayOptionalInputMethod();

    /**
     * @brief Get attach status.
     *
     * This function is used to get status of attach.
     *
     * @return Returns true for attached otherwise for detached.
     * @since 10
     */
    IMF_API bool WasAttached();

    /**
     * @brief Set agent which will be used to communicate with IMA.
     *
     * This function is used to Set agent.
     *
     * @since 10
     */
    IMF_API void OnInputReady(sptr<IRemoteObject> agentObject);

    /**
     * @brief Unbind IMC with Service.
     *
     * This function is unbind imc with service.
     *
     * @since 10
     */
    IMF_API void OnInputStop();

    /**
     * @brief Insert text.
     *
     * This function is used to insert text into editor.
     *
     * @param text Indicates the text which will be inserted.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t InsertText(const std::u16string &text);

    /**
     * @brief Move cursor.
     *
     * This function is used to move cursor according to the direction.
     *
     * @param direction Indicates the direction according to which the cursor will be moved.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t MoveCursor(Direction direction);

    /**
     * @brief Delete forward.
     *
     * This function is used to delete text at the left of cursor.
     *
     * @param length Indicates the length of deleted text.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t DeleteForward(int32_t length);

    /**
     * @brief Delete backward.
     *
     * This function is used to delete text at the right of cursor.
     *
     * @param length Indicates the length of deleted text.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t DeleteBackward(int32_t length);

    /**
     * @brief Get text at the left of cursor.
     *
     * This function is used to get text at the left of cursor.
     *
     * @param length Indicates the length of text.
     * @param text Indicates the text which will be get.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t GetLeft(int32_t length, std::u16string &text);

    /**
     * @brief Get text at the right of cursor.
     *
     * This function is used to get text at the right of cursor.
     *
     * @param length Indicates the length of text.
     * @param text Indicates the text which will be get.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t GetRight(int32_t length, std::u16string &text);

    /**
     * @brief Select text in editor by range.
     *
     * This function is used to select text in editor by range.
     *
     * @param start Indicates the beginning of the range.
     * @param start Indicates the end of the range.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API void SelectByRange(int32_t start, int32_t end);

    /**
     * @brief Select text in editor by cursor movement.
     *
     * This function is used to select text in editor by cursor movement.
     *
     * @param direction Indicates the direction of cursor movement.
     * @param cursorMoveSkip Indicates the skip of cursor movement.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API void SelectByMovement(int32_t direction, int32_t cursorMoveSkip);

    /**
     * @brief Handle extend action code.
     *
     * This function is used to handle extend action code.
     *
     * @param action Indicates the action code which will be handled.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t HandleExtendAction(int32_t action);

    /**
     * @brief Get the index number of text at cursor.
     *
     * This function is used to get the index number of text at cursor.
     *
     * @param index Indicates the index number of text at cursor.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t GetTextIndexAtCursor(int32_t &index);

    /**
     * @brief Send keyboard status.
     *
     * This function is used to send keyboard status to editor.
     *
     * @param status Indicates the status of keyboard.
     * @since 10
     */
    IMF_API void SendKeyboardStatus(int32_t status);

    /**
     * @brief Send function key.
     *
     * This function is used to send function key to editor.
     *
     * @param functionKey Indicates the function key.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t SendFunctionKey(int32_t functionKey);

    /**
     * @brief Inform the change of ime to client.
     *
     * This function is used to inform the change of ime to client.
     *
     * @param property Indicates the property of ime.
     * @param subProperty Indicates the sub property of ime.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t OnSwitchInput(const Property &property, const SubProperty &subProperty);

    /**
     * @brief Inform the change panel status.
     *
     * This function is used to inform the change panel status.
     *
     * @param status Indicates the status of panel.
     * @param windowInfo Indicates the detailed info of window.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t OnPanelStatusChange(
        const InputWindowStatus &status, const std::vector<InputWindowInfo> &windowInfo);

    /**
     * @brief Query whether an input type is supported.
     *
     * This function is used to query whether an input type is supported.
     *
     * @param type Indicates the input type being queried.
     * @return Returns true for supported, false for not supported.
     * @since 10
     */
    IMF_API bool IsInputTypeSupported(InputType type);

    /**
     * @brief Start the input method which provides the specific input type.
     *
     * This function is used to start the input method which provides the specific input type.
     *
     * @param type Indicates the input type being specified.
     * @return Returns 0 for success, others for failure.
     * @since 10
     */
    IMF_API int32_t StartInputType(InputType type);

private:
    InputMethodController();
    ~InputMethodController();

    int32_t Initialize();
    sptr<IInputMethodSystemAbility> GetSystemAbilityProxy();
    int32_t StartInput(InputClientInfo &inputClientInfo, sptr<IRemoteObject> &agnet);
    int32_t ShowInput(sptr<IInputClient> &client);
    int32_t HideInput(sptr<IInputClient> &client);
    int32_t ReleaseInput(sptr<IInputClient> &client);
    int32_t ListInputMethodCommon(InputMethodStatus status, std::vector<Property> &props);
    void ClearEditorCache();
    void OnRemoteSaDied(const wptr<IRemoteObject> &object);
    void RestoreListenInfoInSaDied();
    void RestoreAttachInfoInSaDied();
    int32_t RestoreListenEventFlag();
    void UpdateNativeEventFlag(EventType eventType, bool isOn);
    void SaveTextConfig(const TextConfig &textConfig);
    sptr<OnTextChangedListener> GetTextListener();
    void SetTextListener(sptr<OnTextChangedListener> listener);

    std::shared_ptr<InputMethodSettingListener> settingListener_;
    std::shared_ptr<ControllerListener> controllerListener_;
    std::mutex abilityLock_;
    sptr<IInputMethodSystemAbility> abilityManager_ = nullptr;
    sptr<InputDeathRecipient> deathRecipient_;
    std::mutex agentLock_;
    sptr<IRemoteObject> agentObject_ = nullptr;
    std::shared_ptr<IInputMethodAgent> agent_ = nullptr;
    std::mutex textListenerLock_;
    sptr<OnTextChangedListener> textListener_ = nullptr;
    std::atomic_bool isDiedAttached_{ false };

    std::mutex cursorInfoMutex_;
    CursorInfo cursorInfo_;

    std::mutex editorContentLock_;
    std::u16string textString_;
    int selectOldBegin_ = 0;
    int selectOldEnd_ = 0;
    int selectNewBegin_ = 0;
    int selectNewEnd_ = 0;

    static std::mutex instanceLock_;
    static sptr<InputMethodController> instance_;
    static std::shared_ptr<AppExecFwk::EventHandler> handler_;

    std::atomic_bool isEditable_{ false };
    std::atomic_bool isBound_{ false };

    std::recursive_mutex clientInfoLock_;
    InputClientInfo clientInfo_;

    static constexpr int CURSOR_DIRECTION_BASE_VALUE = 2011;
    std::atomic_bool isDiedRestoreListen_{ false };

    std::mutex textConfigLock_;
    TextConfig textConfig_;
};
} // namespace MiscServices
} // namespace OHOS
#endif // FRAMEWORKS_INPUTMETHOD_CONTROLLER_INCLUDE_INPUT_METHOD_CONTROLLER_H
