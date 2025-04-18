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

#ifndef INPUTMETHOD_IMF_PANEL_LISTENER_IMPL_H
#define INPUTMETHOD_IMF_PANEL_LISTENER_IMPL_H

#include <mutex>
#include <thread>
#include <tuple>
#include <uv.h>

#include "concurrent_map.h"
#include "event_handler.h"
#include "input_method_panel.h"
#include "js_callback_object.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "panel_status_listener.h"

namespace OHOS {
namespace MiscServices {
struct JsWindowSize {
    static napi_value Write(napi_env env, const WindowSize &nativeObject);
    static bool Read(napi_env env, napi_value jsObject, WindowSize &nativeObject);
};
struct JsKeyboardArea {
    static napi_value Write(napi_env env, const PanelAdjustInfo &nativeObject);
    static bool Read(napi_env env, napi_value jsObject, PanelAdjustInfo &nativeObject);
};
class PanelListenerImpl : public PanelStatusListener {
public:
    struct UvEntry {
        WindowSize size;
        PanelAdjustInfo keyboardArea;
        std::shared_ptr<JSCallbackObject> cbCopy;
        explicit UvEntry(const std::shared_ptr<JSCallbackObject> &cb) : cbCopy(cb)
        {
        }
    };
    using EntrySetter = std::function<void(UvEntry &)>;
    static std::shared_ptr<PanelListenerImpl> GetInstance();
    ~PanelListenerImpl();
    void OnPanelStatus(uint32_t windowId, bool isShow) override;
    void OnSizeChange(uint32_t windowId, const WindowSize &size) override;
    void OnSizeChange(uint32_t windowId, const WindowSize &size, const PanelAdjustInfo &keyboardArea,
        const std::string &event) override;
    void Subscribe(uint32_t windowId, const std::string &type, std::shared_ptr<JSCallbackObject> cbObject);
    void RemoveInfo(const std::string &type, uint32_t windowId);
    void SetEventHandler(std::shared_ptr<AppExecFwk::EventHandler> handler);
    std::shared_ptr<JSCallbackObject> GetCallback(uint32_t windowId, const std::string &type);
    std::shared_ptr<AppExecFwk::EventHandler> GetEventHandler();

    ConcurrentMap<uint32_t, std::map<std::string, std::shared_ptr<JSCallbackObject>>> callbacks_;
    static std::mutex listenerMutex_;
    static std::shared_ptr<PanelListenerImpl> instance_;
    mutable std::shared_mutex eventHandlerMutex_;
    std::shared_ptr<AppExecFwk::EventHandler> handler_;
};
} // namespace MiscServices
} // namespace OHOS

#endif //INPUTMETHOD_IMF_PANEL_LISTENER_IMPL_H
