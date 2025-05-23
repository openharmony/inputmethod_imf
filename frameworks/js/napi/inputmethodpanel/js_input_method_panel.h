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

#ifndef INTERFACE_JS_INPUT_METHOD_PANEL
#define INTERFACE_JS_INPUT_METHOD_PANEL

#include "napi/native_api.h"

namespace OHOS {
namespace MiscServices {
class JsInputMethodPanel {
public:
    JsInputMethodPanel() = default;
    ~JsInputMethodPanel() = default;
    static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value GetJsPanelTypeProperty(napi_env env);
    static napi_value GetJsPanelFlagProperty(napi_env env);
};
} // namespace MiscServices
} // namespace OHOS
#endif // INTERFACE_JS_INPUT_METHOD_PANEL