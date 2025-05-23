/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef SCREEN_DECISION_CENTER_TEST_H
#define SCREEN_DECISION_CENTER_TEST_H

#include <gtest/gtest.h>
#include "screen_decision_center.h"
#include "video_param.h"
namespace OHOS {
namespace DistributedHardware {
class ScreenDecisionCenterTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    VideoParam param_;
    std::shared_ptr<ScreenDecisionCenter> decision = nullptr;
};

class ImageSourceProcessorStub : public ImageSourceProcessor {
public:
    ImageSourceProcessorStub() = default;
    ~ImageSourceProcessorStub() = default;
    int32_t ProcessFullImage(sptr<SurfaceBuffer> &surfaceBuffer)
    {
        return 0;
    }
};

class JpegImageProcessorStub : public JpegImageProcessor {
public:
    explicit JpegImageProcessorStub(const VideoParam &configParam) : JpegImageProcessor(configParam) {};
    ~JpegImageProcessorStub() = default;

    int32_t ProcessDamageSurface(sptr<SurfaceBuffer> &surfaceBuffer, const std::vector<OHOS::Rect> &damages)
    {
        return 0;
    }
};
} // namespace DistributedHardware
} // namespace OHOS
#endif