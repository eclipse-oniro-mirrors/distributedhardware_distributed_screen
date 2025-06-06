/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_IMAGE_SOURCE_ENCODER_TEST_H
#define OHOS_IMAGE_SOURCE_ENCODER_TEST_H

#include <gtest/gtest.h>
#include <securec.h>

#include "dscreen_constants.h"
#include "dscreen_errcode.h"
#include "dscreen_log.h"
#include "image_source_encoder.h"

namespace OHOS {
namespace DistributedHardware {
class ImageSourceEncoderTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<ImageSourceEncoder> encoder = nullptr;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif