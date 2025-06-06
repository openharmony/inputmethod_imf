/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "imf_hisysevent_util.h"

#include <algorithm>

#include "accesstoken_kit.h"
#include "app_mgr_client.h"
#include "hisysevent.h"
#include "ipc_skeleton.h"
#include "running_process_info.h"
#include "singleton.h"
namespace OHOS {
namespace MiscServices {
using namespace OHOS::AppExecFwk;
using HiSysEvent = OHOS::HiviewDFX::HiSysEvent;
using namespace Security::AccessToken;
void ImfHiSysEventUtil::ReportClientAttachFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "CLIENT_ATTACH_FAILED", HiSysEvent::EventType::FAULT,
        "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid, "PEER_USERID", info.peerUserId,
        "CLIENT_TYPE", info.clientType, "INPUT_PATTERN", info.inputPattern, "ISSHOWKEYBOARD", info.isShowKeyboard,
        "IME_NAME", info.imeName, "ERR_CODE", info.errCode, "FAULT_COUNT", faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d", ret);
    }
}

void ImfHiSysEventUtil::ReportClientShowFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "CLIENT_SHOW_FAILED", HiSysEvent::EventType::FAULT,
        "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid, "PEER_USERID", info.peerUserId,
        "CLIENT_TYPE", info.clientType, "INPUT_PATTERN", info.inputPattern, "IME_NAME", info.imeName, "EVENT_CODE",
        info.eventCode, "ERR_CODE", info.errCode, "FAULT_COUNT", faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d", ret);
    }
}

void ImfHiSysEventUtil::ReportImeStartInputFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "IME_START_INPUT_FAILED", HiSysEvent::EventType::FAULT,
        "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid, "ISSHOWKEYBOARD",
        info.isShowKeyboard, "EVENT_CODE", info.eventCode, "ERR_CODE", info.errCode, "FAULT_COUNT", faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d", ret);
    }
}

void ImfHiSysEventUtil::ReportBaseTextOperationFault(
    const std::string &selfName, int64_t faultNum, const HiSysOriginalInfo &info)
{
    IMSA_HILOGD("run in.");
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, "BASE_TEXT_OPERATION_FAILED",
        HiSysEvent::EventType::FAULT, "SELF_NAME", selfName, "PEER_NAME", info.peerName, "PEER_PID", info.peerPid,
        "CLIENT_TYPE", info.clientType, "EVENT_CODE", info.eventCode, "ERR_CODE", info.errCode, "FAULT_COUNT",
        faultNum);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d", ret);
    }
}

void ImfHiSysEventUtil::ReportStatisticsEvent(const std::string &eventName, const std::vector<std::string> &imeNames,
    const std::vector<std::string> &appNames, const std::vector<std::string> &statistics)
{
    std::string infoStr;
    if (!statistics.empty()) {
        infoStr = statistics[0];
    }
    IMSA_HILOGD("run in, [%{public}s, %{public}s].", eventName.c_str(), infoStr.c_str());
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, eventName, HiSysEvent::EventType::STATISTIC,
        "IME_NAME", imeNames, "APP_NAME", appNames, "INFOS", statistics);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d", ret);
    }
}

void ImfHiSysEventUtil::ReportStatisticsEvent(const std::string &eventName, const std::string &imeName,
    const std::vector<std::string> &appNames, const std::vector<std::string> &statistics)
{
    std::string infoStr;
    if (!statistics.empty()) {
        infoStr = statistics[0];
    }
    IMSA_HILOGD("run in, [%{public}s, %{public}s].", eventName.c_str(), infoStr.c_str());
    auto ret = HiSysEventWrite(HiSysEvent::Domain::INPUTMETHOD, eventName, HiSysEvent::EventType::STATISTIC,
        "SELF_NAME", imeName, "APP_NAME", appNames, "INFOS", statistics);
    if (ret != HiviewDFX::SUCCESS) {
        IMSA_HILOGE("report failed! ret: %{public}d", ret);
    }
}

std::string ImfHiSysEventUtil::GetAppName(uint64_t fullTokenId)
{
    std::string name;
    uint32_t tokenId = static_cast<uint32_t>(fullTokenId);
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    switch (tokenType) {
        case ATokenTypeEnum::TOKEN_HAP: {
            if (fullTokenId == IPCSkeleton::GetSelfTokenID()) {
                RunningProcessInfo info;
                auto appMgrClient = DelayedSingleton<AppMgrClient>::GetInstance();
                if (appMgrClient != nullptr && appMgrClient->GetProcessRunningInformation(info) == 0) {
                    name = info.processName_;
                }
                break;
            }
            HapTokenInfo hapInfo;
            if (AccessTokenKit::GetHapTokenInfo(tokenId, hapInfo) == 0) {
                name = hapInfo.bundleName;
            }
            break;
        }
        case ATokenTypeEnum::TOKEN_NATIVE:
        case ATokenTypeEnum::TOKEN_SHELL: {
            NativeTokenInfo tokenInfo;
            if (AccessTokenKit::GetNativeTokenInfo(tokenId, tokenInfo) == 0) {
                name = tokenInfo.processName;
            }
            break;
        }
        default: {
            break;
        }
    }
    return name;
}

std::string ImfHiSysEventUtil::AddIfAbsent(const std::string &bundleName, std::vector<std::string> &bundleNames)
{
    auto it = std::find_if(bundleNames.begin(), bundleNames.end(),
        [&bundleName](const std::string &bundleNameTmp) { return bundleName == bundleNameTmp; });
    if (it == bundleNames.end()) {
        bundleNames.push_back(bundleName);
        return std::to_string(bundleNames.size() - 1);
    }
    return std::to_string(it - bundleNames.begin());
}
} // namespace MiscServices
} // namespace OHOS