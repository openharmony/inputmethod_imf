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

#include "serializable.h"

namespace OHOS {
namespace MiscServices {
bool Serializable::Unmarshall(const std::string &content)
{
    auto root = cJSON_Parse(content.c_str());
    if (root == NULL) {
        IMSA_HILOGE("content parse failed!");
        return false;
    }
    auto ret = Unmarshal(root);
    cJSON_Delete(root);
    return ret;
}

bool Serializable::Marshall(std::string &content) const
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return false;
    }
    auto ret = Marshal(root);
    if (!ret) {
        cJSON_Delete(root);
        return false;
    }
    auto str = cJSON_PrintUnformatted(root);
    if (str == NULL) {
        cJSON_Delete(root);
        return false;
    }
    content = str;
    cJSON_Delete(root);
    cJSON_free(str);
    return true;
}

bool Serializable::GetValue(cJSON *node, const std::string &name, std::string &value)
{
    auto subNode = GetSubNode(node, name);
    if (subNode == nullptr || !cJSON_IsString(subNode)) {
        IMSA_HILOGD("%{public}s not string!", name.c_str());
        return false;
    }
    value = subNode->valuestring;
    return true;
}

bool Serializable::GetValue(cJSON *node, const std::string &name, int32_t &value)
{
    auto subNode = GetSubNode(node, name);
    if (subNode == nullptr || !cJSON_IsNumber(subNode)) {
        IMSA_HILOGD("%{public}s not number!", name.c_str());
        return false;
    }
    value = subNode->valueint;
    return true;
}

bool Serializable::GetValue(cJSON *node, const std::string &name, uint32_t &value)
{
    auto subNode = GetSubNode(node, name);
    if (!cJSON_IsNumber(subNode)) {
        IMSA_HILOGD("%{public}s not number", name.c_str());
        return false;
    }
    // Make sure it's not negative
    if (subNode->valueint < 0) {
        IMSA_HILOGD("%{public}s is negative", name.c_str());
        return false;
    }
    value = static_cast<uint32_t>(subNode->valueint);
    return true;
}

bool Serializable::GetValue(cJSON *node, const std::string &name, bool &value)
{
    auto subNode = GetSubNode(node, name);
    if (subNode == nullptr || !cJSON_IsBool(subNode)) {
        IMSA_HILOGD("%{public}s not bool", name.c_str());
        return false;
    }
    value = subNode->type == cJSON_True;
    return true;
}

bool Serializable::GetValue(cJSON *node, const std::string &name, Serializable &value)
{
    auto object = GetSubNode(node, name);
    if (object == nullptr || !cJSON_IsObject(object)) {
        IMSA_HILOGD("%{public}s not object", name.c_str());
        return false;
    }
    return value.Unmarshal(object);
}

bool Serializable::GetValue(cJSON *node, const std::string &name, std::vector<std::vector<std::string>> &values)
{
    auto arrNode = GetSubNode(node, name);
    if (arrNode == nullptr || !cJSON_IsArray(arrNode)) {
        IMSA_HILOGD("%{public}s not array", name.c_str());
        return false;
    }
    auto arrLen = cJSON_GetArraySize(arrNode);
    for (auto i = 0; i < arrLen; i++) {
        auto subArrNode = cJSON_GetArrayItem(arrNode, i);
        if (subArrNode == nullptr || !cJSON_IsArray(subArrNode)) {
            continue;
        }
        std::vector<std::string> subStringArr;
        auto subArrLen = cJSON_GetArraySize(subArrNode);
        for (auto j = 0; j < subArrLen; j++) {
            auto strNode = cJSON_GetArrayItem(subArrNode, j);
            if (strNode == nullptr || !cJSON_IsString(strNode)) {
                continue;
            }
            subStringArr.push_back(strNode->valuestring);
        }
        values.push_back(subStringArr);
    }
    return true;
}

bool Serializable::SetValue(cJSON *node, const std::string &name, const std::string &value)
{
    auto item = cJSON_AddStringToObject(node, name.c_str(), value.c_str());
    return item != NULL;
}

bool Serializable::SetValue(cJSON *node, const std::string &name, const int32_t &value)
{
    auto item = cJSON_AddNumberToObject(node, name.c_str(), value);
    return item != NULL;
}

bool Serializable::SetValue(cJSON *node, const std::string &name, const bool &value)
{
    auto item = cJSON_AddBoolToObject(node, name.c_str(), value);
    return item != NULL;
}

bool Serializable::SetValue(cJSON *node, const std::string &name, const Serializable &value)
{
    cJSON *item = cJSON_CreateObject();
    if (item == NULL) {
        return false;
    }
    if (!value.Marshal(item)) {
        cJSON_Delete(item);
        return false;
    }
    auto ret = cJSON_AddItemToObject(node, name.c_str(), item);
    if (!ret) {
        cJSON_Delete(item);
    }
    return ret;
}

bool Serializable::SetValue(cJSON *node, const std::string &name, const std::vector<std::string> &values)
{
    const char **strArr = new (std::nothrow) const char *[values.size()];
    if (strArr == nullptr) {
        return false;
    }
    for (size_t i = 0; i < values.size(); i++) {
        strArr[i] = values[i].c_str();
    }
    cJSON *stringArray = cJSON_CreateStringArray(strArr, values.size());
    if (stringArray == NULL) {
        delete[] strArr;
        return false;
    }

    auto ret = cJSON_AddItemToObject(node, name.c_str(), stringArray);
    if (!ret) {
        cJSON_Delete(stringArray);
    }
    delete[] strArr;
    return ret;
}

bool Serializable::SetValue(cJSON *node, const std::string &name, const std::vector<std::vector<std::string>> &values)
{
    cJSON *array = cJSON_CreateArray();
    if (array == NULL) {
        return false;
    }
    for (const auto &value : values) {
        const char **strArr = new (std::nothrow) const char *[value.size()];
        if (strArr == nullptr) {
            continue;
        }
        for (size_t i = 0; i < value.size(); i++) {
            strArr[i] = value[i].c_str();
        }
        cJSON *stringArray = cJSON_CreateStringArray(strArr, value.size());
        if (stringArray == NULL) {
            delete[] strArr;
            continue;
        }
        auto ret = cJSON_AddItemToArray(array, stringArray);
        if (!ret) {
            cJSON_Delete(stringArray);
        }
        delete[] strArr;
    }
    auto ret = cJSON_AddItemToObject(node, name.c_str(), array);
    if (!ret) {
        cJSON_Delete(array);
    }
    return ret;
}

cJSON *Serializable::GetSubNode(cJSON *node, const std::string &name)
{
    if (name.empty()) {
        IMSA_HILOGD("end node.");
        return node;
    }
    if (!cJSON_IsObject(node)) {
        IMSA_HILOGD("not object, name:%{public}s", name.c_str());
        return nullptr;
    }
    if (!cJSON_HasObjectItem(node, name.c_str())) {
        IMSA_HILOGD("subNode: %{public}s not contain.", name.c_str());
        return nullptr;
    }
    return cJSON_GetObjectItem(node, name.c_str());
}
} // namespace MiscServices
} // namespace OHOS