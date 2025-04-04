/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public

#include "input_method_system_ability.h"
#include "security_mode_parser.h"
#include "settings_data_utils.h"

#undef private

#include <gtest/gtest.h>

using namespace testing::ext;
using namespace OHOS::DataShare;
namespace OHOS {
namespace MiscServices {
const std::string SECURITY_KEY = "settings.inputmethod.full_experience";
constexpr uint32_t USER_100_TOTAL_COUNT = 3;
constexpr uint32_t USER_101_TOTAL_COUNT = 1;
class SecurityModeParserTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    static std::shared_ptr<DataShareHelper> helper_;
    static std::shared_ptr<DataShareResultSet> resultSet_;
    static sptr<InputMethodSystemAbility> service_;
    static constexpr int32_t USER_ID = 100;
};
std::shared_ptr<DataShareHelper> SecurityModeParserTest::helper_;
std::shared_ptr<DataShareResultSet> SecurityModeParserTest::resultSet_;
sptr<InputMethodSystemAbility> SecurityModeParserTest::service_ { nullptr };
void SecurityModeParserTest::SetUpTestCase(void)
{
    IMSA_HILOGI("SecurityModeParserTest::SetUpTestCase");
    std::vector<std::string> columns = { "VALUE" };
    helper_ = DataShare::DataShareHelper::Creator(nullptr, "tsetUri", "tsetUri");
    DataSharePredicates predicates;
    Uri uri("tsetUri");
    resultSet_ = helper_->Query(uri, predicates, columns);
    SecurityModeParser::GetInstance()->Initialize(USER_ID);

    service_ = new (std::nothrow) InputMethodSystemAbility();
    if (service_ == nullptr) {
        IMSA_HILOGE("failed to new service");
        return;
    }
    service_->OnStart();
    service_->userId_ = USER_ID;
}

void SecurityModeParserTest::TearDownTestCase(void)
{
    service_->OnStop();
    IMSA_HILOGI("SecurityModeParserTest::TearDownTestCase");
}

void SecurityModeParserTest::SetUp()
{
    IMSA_HILOGI("SecurityModeParserTest::SetUp");
    resultSet_->strValue_ = "{\"fullExperienceList\" : {\"100\" : [ \"xiaoyiIme\", \"baiduIme\", "
                            "\"sougouIme\"],\"101\" : [\"sougouIme\"]}}";

    SecurityModeParser::GetInstance()->fullModeList_.clear();
}

void SecurityModeParserTest::TearDown()
{
    IMSA_HILOGI("SecurityModeParserTest::TearDown");
}

/**
 * @tc.name: testGetFullModeList_001
 * @tc.desc: Get 101 user fullModeList
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: guojin
 */
HWTEST_F(SecurityModeParserTest, testGetFullModeList_001, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testGetFullModeList_001 START");
    int32_t ret = SecurityModeParser::GetInstance()->UpdateFullModeList(101);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(SecurityModeParser::GetInstance()->fullModeList_.size(), USER_101_TOTAL_COUNT);
    if (SecurityModeParser::GetInstance()->fullModeList_.size() == USER_101_TOTAL_COUNT) {
        EXPECT_EQ(SecurityModeParser::GetInstance()->fullModeList_[0], "sougouIme");
    }
}

/**
 * @tc.name: testGetFullModeList_002
 * @tc.desc: Get 100 user fullModeList
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: guojin
 */
HWTEST_F(SecurityModeParserTest, testGetFullModeList_002, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testGetFullModeList_002 START");
    int32_t ret = SecurityModeParser::GetInstance()->UpdateFullModeList(SecurityModeParserTest::USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(SecurityModeParser::GetInstance()->fullModeList_.size(), USER_100_TOTAL_COUNT);
    if (SecurityModeParser::GetInstance()->fullModeList_.size() == USER_100_TOTAL_COUNT) {
        EXPECT_EQ(SecurityModeParser::GetInstance()->fullModeList_[0], "xiaoyiIme");
        EXPECT_EQ(SecurityModeParser::GetInstance()->fullModeList_[1], "baiduIme");
        EXPECT_EQ(SecurityModeParser::GetInstance()->fullModeList_[2], "sougouIme");
    }
}

/**
 * @tc.name: testGetSecurityMode_001
 * @tc.desc: Get 100 user security mode
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: guojin
 */
HWTEST_F(SecurityModeParserTest, testGetSecurityMode_001, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testGetSecurityMode_001 START");
    int32_t ret = SecurityModeParser::GetInstance()->UpdateFullModeList(SecurityModeParserTest::USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    SecurityMode security =
        SecurityModeParser::GetInstance()->GetSecurityMode("xiaoyiIme", SecurityModeParserTest::USER_ID);
    EXPECT_EQ(static_cast<int32_t>(security), 1);
}

/**
 * @tc.name: testGetSecurityMode_002
 * @tc.desc: Get 100 user security mode
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: guojin
 */
HWTEST_F(SecurityModeParserTest, testGetSecurityMode_002, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testGetSecurityMode_002 START");
    int32_t ret = SecurityModeParser::GetInstance()->UpdateFullModeList(SecurityModeParserTest::USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    SecurityMode security = SecurityModeParser::GetInstance()->GetSecurityMode("test", SecurityModeParserTest::USER_ID);
    EXPECT_EQ(static_cast<int32_t>(security), 0);
}

/**
 * @tc.name: testGetSecurityMode_003
 * @tc.desc: Get 100 user security mode
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: guojin
 */
HWTEST_F(SecurityModeParserTest, testGetSecurityMode_003, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testGetSecurityMode_003 START");
    service_->enableSecurityMode_ = false;
    int32_t securityMode;
    auto ret = service_->GetSecurityMode(securityMode);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(securityMode, 1);
}

/**
 * @tc.name: testGetSecurityMode_004
 * @tc.desc: Get 100 user security mode
 * @tc.type: FUNC
 * @tc.require:
 * @tc.author: guojin
 */
HWTEST_F(SecurityModeParserTest, testGetSecurityMode_004, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testGetSecurityMode_004 START");
    service_->enableSecurityMode_ = true;
    int32_t securityMode;
    auto ret = service_->GetSecurityMode(securityMode);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
    EXPECT_EQ(securityMode, 1);
}

/**
 * @tc.name: testInitialize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecurityModeParserTest, testInitialize, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testInitialize START");
    auto ret = SecurityModeParser::GetInstance()->Initialize(SecurityModeParserTest::USER_ID);
    EXPECT_EQ(ret, ErrorCode::NO_ERROR);
}

/**
 * @tc.name: testIsExpired
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecurityModeParserTest, testIsExpired, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testIsExpired START");
    auto ret = SecurityModeParser::GetInstance()->IsExpired("test");
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: testRegisterObserver
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecurityModeParserTest, testRegisterObserver, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testRegisterObserver START");
    sptr<SettingsDataObserver> observer = nullptr;
    auto ret = SettingsDataUtils::GetInstance()->RegisterObserver(observer);
    EXPECT_EQ(ret, ErrorCode::ERROR_NULL_POINTER);
}

/**
 * @tc.name: testReleaseDataShareHelper
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecurityModeParserTest, testReleaseDataShareHelper, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testReleaseDataShareHelper START");
    std::shared_ptr<DataShare::DataShareHelper> helper;
    auto ret = SettingsDataUtils::GetInstance()->ReleaseDataShareHelper(helper);
    EXPECT_TRUE(ret);
    helper = nullptr;
    ret = SettingsDataUtils::GetInstance()->ReleaseDataShareHelper(helper);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: testParseSecurityMode_001
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecurityModeParserTest, testParseSecurityMode_001, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testParseSecurityMode_001 START");
    auto ret = SecurityModeParser::GetInstance()->ParseSecurityMode("", SecurityModeParserTest::USER_ID);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: testParseSecurityMode_002
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SecurityModeParserTest, testParseSecurityMode_002, TestSize.Level1)
{
    IMSA_HILOGI("SecurityModeParserTest testParseSecurityMode_002 START");
    auto ret = SecurityModeParser::GetInstance()->ParseSecurityMode(
        "{\"fullExperienceList\" : {\"100\" : ["
        "\"xiaoyiIme\", \"baiduIme\", \"sougouIme\"],\"101\" : [\"sougouIme\"]}}",
        SecurityModeParserTest::USER_ID);
    EXPECT_TRUE(ret);
}
} // namespace MiscServices
} // namespace OHOS