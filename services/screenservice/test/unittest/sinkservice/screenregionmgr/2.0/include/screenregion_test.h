/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_SCREEN_REGION_TEST_V2_0_H
#define OHOS_SCREEN_REGION_TEST_V2_0_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "dscreen_errcode.h"
#include "screen_sink_trans.h"
#include "2.0/include/screenregion.h"

namespace OHOS {
namespace DistributedHardware {
namespace V2_0 {
class ScreenRegionTestV2 : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<ScreenRegion> screenRegion_ = nullptr;
};

class MockAVReceiverAdapterCallback : public AVReceiverAdapterCallback {
public:
    explicit MockAVReceiverAdapterCallback() {}
    ~MockAVReceiverAdapterCallback() {}
    void OnEngineEvent(DScreenEventType event, const std::string &content) override {}
    void OnEngineMessage(const std::shared_ptr<AVTransMessage> &message) override {}
    void OnEngineDataDone(const std::shared_ptr<AVTransBuffer> &buffer) override {}
};
} // namespace V2_0
} // namespace DistributedHardware
} // namespace OHOS
#endif