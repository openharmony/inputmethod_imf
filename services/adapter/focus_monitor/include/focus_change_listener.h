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

#ifndef IMF_FOCUS_CHANGE_LISTENER_H
#define IMF_FOCUS_CHANGE_LISTENER_H

#include "focus_monitor_manager.h"
#ifdef SCENE_BOARD_ENABLE
#include "window_manager_lite.h"
#else
#include "window_manager.h"
#endif

namespace OHOS {
namespace MiscServices {
class FocusChangedListener : public Rosen::IFocusChangedListener {
public:
    explicit FocusChangedListener(const FocusHandle &handle) : focusHandle_(handle){};
    ~FocusChangedListener() = default;
    void OnFocused(const sptr<Rosen::FocusChangeInfo> &focusChangeInfo) override;
    void OnUnfocused(const sptr<Rosen::FocusChangeInfo> &focusChangeInfo) override;

private:
    FocusHandle focusHandle_ = nullptr;
};
} // namespace MiscServices
} // namespace OHOS

#endif // IMF_FOCUS_CHANGE_LISTENER_H
