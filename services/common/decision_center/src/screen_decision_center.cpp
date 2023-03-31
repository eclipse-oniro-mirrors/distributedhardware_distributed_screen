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

#include "screen_decision_center.h"

#include "dscreen_constants.h"
#include "dscreen_errcode.h"
#include "dscreen_log.h"

namespace OHOS {
namespace DistributedHardware {
bool ScreenDecisionCenter::IsDirtyRectValid(const std::vector<OHOS::Rect> &damages)
{
    DHLOGI("%s: IsDirtyRectValid.", LOG_TAG);
    if (damages.empty()) {
        DHLOGE("%s: damages size is empty.", LOG_TAG);
        return false;
    }
    for (const auto &damage : damages) {
        if (damage.x < 0 || damage.x > configParam_.GetScreenWidth() ||
            damage.y < 0 || damage.y > configParam_.GetScreenHeight()) {
            DHLOGE("%s: dirty x and y invalied.", LOG_TAG);
            return false;
        }
        int32_t width = configParam_.GetScreenWidth() - damage.x;
        int32_t height = configParam_.GetScreenHeight() - damage.y;
        if (damage.x % EVEN == ODD || damage.w % EVEN == ODD) {
            DHLOGE("%s: dirty x and w invalied.", LOG_TAG);
            return false;
        }
        if (damage.w < 0 || damage.w > width || damage.h < 0 || damage.h > height) {
            DHLOGE("%s: dirty invalied.", LOG_TAG);
            return false;
        }    
    }
    return true;
}
bool ScreenDecisionCenter::JudgeDirtyThreshold(const std::vector<OHOS::Rect> &damages)
{
    DHLOGI("%s: JudgeDirtyThreshold.", LOG_TAG);
    int32_t allDirtyArea = 0;
    for (const auto &damage : damages) {
        int32_t dirtyArea = damage.w * damage.h;
        allDirtyArea += dirtyArea;
        if (dirtyArea > ARE_THRESHOLD || allDirtyArea > ARE_THRESHOLD) {
            DHLOGE("%s: dirtyArea is %.", PRId32, LOG_TAG, dirtyArea);
            return false;
        }
    }
    return true;
}
bool ScreenDecisionCenter::LimitTime(uint32_t timethreshold)
{
    return difftime(time(nullptr), sendFullTime_) >= timethreshold;
}

int32_t ScreenDecisionCenter::InputBufferDmage(sptr<SurfaceBuffer> &surfaceBuffer,
    const std::vector<OHOS::Rect> &damages)
{
    DHLOGI("%s: InputBufferDmage.", LOG_TAG);
    if (surfaceBuffer == nullptr) {
        DHLOGE("%s: surfaceBuffer is null.", LOG_TAG);
        return ERR_DH_SCREEN_SURFACE_BUFFER_INVALIED;
    }
    if (damages.empty() || frameCount_ < THRESHOLD || LimitTime(THRESHOLD) ||
        !IsDirtyRectValid(damages) || !JudgeDirtyThreshold(damages)) {
        DHLOGI("%s: send full image data.", LOG_TAG);
        sendFullTime_ = time(nullptr);
        int32_t ret = imageProcessor_->ProcessFullIma ge(surfaceBuffer);
        if (ret != DH_SUCCESS) {
            DHLOGE("%s: send full data failed.", LOG_TAG);
            return ret;
        }
    } else {
        DHLOGI("%s: send dirty data.", LOG_TAG);
        int32_t ret = imageJpeg_->ProcessPartailImage(surfaceBuffer, damages);
        if (ret != DH_SUCCESS) {
            DHLOGE("%s: send dirty data failed.", LOG_TAG);
            return ret;
        }
    }
    frameCount_++;
    return DH_SUCCESS;
}
int32_t ScreenDecisionCenter::ConfigureDecisionCenter(std::shared_ptr<IImageSourceProcessorListener> &listener,
        std::shared_ptr<IImageSourceProcessor> &imageProcessor)
{
    DHLOGI("%s: ConfigureDecisionCenter.", LOG_TAG);
    if (listener == nullptr || imageProcessor == nullptr) {
        DHLOGE("%s: Image source process is null.", LOG_TAG);
        return ERR_DH_SCREEN_TRANS_NULL_VALUE;
    }
    imageJpeg_ = std::make_shared<ScreenImageJpeg>(configParam_);
    imageJpeg_->SetImageProcessListener(listener);
    imageProcessor_ = imageProcessor;
    return DH_SUCCESS;
}
int32_t ScreenDecisionCenter::SetJpegSurface(sptr<Surface> &surface)
{
    DHLOGI("%s: SetJpegSurface.", LOG_TAG);
    int32_t ret = imageJpeg_->SetOutputSurface(surface);
    if (ret != DH_SUCCESS) {
        DHLOGE("%s: JPEG set surface failed.", LOG_TAG);
        return ret;
    }
    return DH_SUCCESS;  
}
} // namespace DistributedHardware
} // namespace OHOS