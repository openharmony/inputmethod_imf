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

#ifndef OHOS_MISCSERVICES_JS_INPUT_METHOD_ENGINE_REGISTRY_H
#define OHOS_MISCSERVICES_JS_INPUT_METHOD_ENGINE_REGISTRY_H

#include "native_engine/native_engine.h"
#include "native_engine/native_value.h"
#include "js_runtime_utils.h"
#include "js_input_method_engine.h"
#include "js_keyboard_controller.h"
#include "js_text_input_client.h"
#include "js_keyboard_delegate.h"

namespace OHOS {
    namespace MiscServices {
        NativeValue* JsInputMethodEngineRegistryInit(NativeEngine* engine, NativeValue* exportObj);
    }
}

#endif // OHOS_MISCSERVICES_JS_INPUT_METHOD_ENGINE_REGISTRY_H