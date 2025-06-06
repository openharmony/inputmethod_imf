/*
 * Copyright (c) 2022-2022 Huawei Device Co., Ltd.
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

#include "inputmethod_trace.h"

#include "hitrace_meter.h"

namespace OHOS {
namespace MiscServices {
constexpr uint64_t HITRACE_TAG_MISC = (1ULL << 41); // Notification module tag.
void InitHiTrace()
{
    UpdateTraceLabel();
}

void ValueTrace(const std::string &name, int64_t count)
{
    CountTrace(HITRACE_TAG_MISC, name, count);
}

void StartAsync(const std::string &value, int32_t taskId)
{
    StartAsyncTrace(HITRACE_TAG_MISC, value, taskId);
}

void FinishAsync(const std::string &value, int32_t taskId)
{
    FinishAsyncTrace(HITRACE_TAG_MISC, value, taskId);
}

InputMethodSyncTrace::InputMethodSyncTrace(const std::string &value)
{
    StartTrace(HITRACE_TAG_MISC, value);
}

InputMethodSyncTrace::InputMethodSyncTrace(const std::string &value, const std::string &id)
{
    auto info = value + "_" + id;
    StartTrace(HITRACE_TAG_MISC, info);
}

InputMethodSyncTrace::~InputMethodSyncTrace()
{
    FinishTrace(HITRACE_TAG_MISC);
}
} // namespace MiscServices
} // namespace OHOS