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

#include "jpeg_image_processor.h"

#include <cstring>
#include <fstream>
#include <iostream>
#include "jpeglib.h"
#include <securec.h>
#include <string>

#ifdef LIBYUV
#include <libyuv/convert_from_argb.h>
#endif

#include "dscreen_errcode.h"
#include "dscreen_log.h"

namespace OHOS {
namespace DistributedHardware {
int32_t JpegImageProcessor::SetOutputSurface(sptr<Surface> surface)
{
    DHLOGI("%s: SetOutputSurface.", LOG_TAG);
    if (surface == nullptr) {
        DHLOGE("%s: SetOutputSurface surface is nullptr.", LOG_TAG);
        return ERR_DH_SCREEN_TRANS_NULL_VALUE;
    }
    imageSurface_ = surface;
    return DH_SUCCESS;
}

int32_t JpegImageProcessor::FillDirtyImages2Surface(const std::shared_ptr<DataBuffer> &data, uint8_t *lastFrame)
{
    DHLOGI("%s: FillDirtyImages2Surface.", LOG_TAG);
    if (imageSurface_ == nullptr) {
        DHLOGE("%s: imageSurface_ is nullptr.", LOG_TAG);
        return ERR_DH_SCREEN_SURFACE_INVALIED;
    }
    int32_t lastFrameSize = configParam_.GetScreenWidth() * configParam_.GetScreenHeight() * RGB_CHROMA / TWO;
    int32_t ret = DecodeDamageData(data, lastFrame);
    if (ret != DH_SUCCESS) {
        DHLOGE("%s: Merge dirty failed, ret: %." PRId32, LOG_TAG, ret);
        return ret;
    }
    sptr<OHOS::SurfaceBuffer> windowSurfaceBuffer = nullptr;
    int32_t releaseFence = -1;
    OHOS::BufferRequestConfig requestConfig = {
        .width = configParam_.GetScreenWidth(),
        .height = configParam_.GetScreenHeight(),
        .strideAlignment = STRIDE_ALIGNMENT,
        .format = PIXEL_FMT_YCBCR_420_SP,
        .usage = HBM_USE_CPU_READ | HBM_USE_CPU_WRITE | HBM_USE_MEM_DMA,
    };
    SurfaceError surfaceErr = imageSurface_->RequestBuffer(windowSurfaceBuffer, releaseFence, requestConfig);
    if (surfaceErr != SURFACE_ERROR_OK || windowSurfaceBuffer == nullptr) {
        DHLOGE("%s: imageSurface request buffer failed, surfaceErr: %." PRId32, LOG_TAG, surfaceErr);
        imageSurface_->CancelBuffer(windowSurfaceBuffer);
        return surfaceErr;
    }
    int32_t surfaceBuffeSize = windowSurfaceBuffer->GetSize();
    auto windowSurfaceAddr = static_cast<uint8_t*>(windowSurfaceBuffer->GetVirAddr());
    ret = memcpy_s(windowSurfaceAddr, surfaceBuffeSize, lastFrame, lastFrameSize);
    if (ret != DH_SUCCESS) {
        DHLOGE("%s: memcpy lastFrame failed,ret: %." PRId32, LOG_TAG, ret);
        imageSurface_->CancelBuffer(windowSurfaceBuffer);
        return ret;
    }
    BufferFlushConfig flushConfig = { {0, 0, windowSurfaceBuffer->GetWidth(), windowSurfaceBuffer-> GetHeight()}, 0};
    surfaceErr = imageSurface_->FlushBuffer(windowSurfaceBuffer, -1, flushConfig);
    if (surfaceErr != SURFACE_ERROR_OK) {
        DHLOGE("%s: imageSurface flush buffer failed, surfaceErr: %." PRId32, LOG_TAG, surfaceErr);
        imageSurface_->CancelBuffer(windowSurfaceBuffer);
        return surfaceErr;
    }
    DHLOGI("%s: FillDirtyImages2Surface success.", LOG_TAG);
    return DH_SUCCESS;
}

int32_t JpegImageProcessor::ProcessDamageSurface(sptr<SurfaceBuffer> &surfaceBuffer,
    const std::vector<OHOS::Rect> &damages)
{
    DHLOGI("%s: ProcessDamageSurface.", LOG_TAG);
    std::shared_ptr<DataBuffer> dataBuf = std::make_shared<DataBuffer>(configParam_.GetScreenWidth() *
        configParam_.GetScreenHeight() * RGBA_CHROMA);
    dataBuf->SetSize(0);
    for (auto item : damages) {
        EncodeDamageData(surfaceBuffer, item, dataBuf);
    }
    std::shared_ptr<IImageSourceProcessorListener> listener = imageProcessorListener_.lock();
    if (listener == nullptr) {
        DHLOGE("%s: Processor listener is null.", LOG_TAG);
        imageSurface_->ReleaseBuffer(surfaceBuffer, -1);
        return ERR_DH_SCREEN_CODEC_SURFACE_ERROR;
    }
    dataBuf->SetDataType(VIDEO_PART_SCREEN_DATA);
    listener->OnImageProcessDone(dataBuf);
    return DH_SUCCESS;
}

int32_t JpegImageProcessor::SetImageProcessListener(std::shared_ptr<IImageSourceProcessorListener> &listener)
{
    DHLOGI("%s: SetImageProcessorListener.", LOG_TAG);
    imageProcessorListener_ = listener;
    return DH_SUCCESS;
}

void JpegImageProcessor::EncodeDamageData(sptr<SurfaceBuffer> &surfaceBuffer,
    const OHOS::Rect &damage, std::shared_ptr<DataBuffer> &data)
{
    DHLOGI("%s: EncodeDamageData.", LOG_TAG);
    int32_t partialSize = damage.w * damage.h *RGBA_CHROMA;
    unsigned char *partialBuffer = new unsigned char[partialSize];
    unsigned char *partialBufferIdx = partialBuffer;
    auto surfaceAddrIdx = static_cast<uint8_t*>(surfaceBuffer->GetVirAddr());
    surfaceAddrIdx += damage.y * configParam_.GetScreenWidth() * RGBA_CHROMA + damage.x * RGBA_CHROMA;
    for (int32_t row = 0 ; row < damage.h ; row++) {
        int32_t ret = memcpy_s(partialBufferIdx, damage.w * RGBA_CHROMA, surfaceAddrIdx, damage.w * RGBA_CHROMA);
        if (ret != DH_SUCCESS) {
            DHLOGE("%s: get partail data failed.", LOG_TAG);
            imageSurface_->ReleaseBuffer(surfaceBuffer, -1);
            delete [] partialBuffer;
            return;
        }
        partialBufferIdx += damage.w * RGBA_CHROMA;
        surfaceAddrIdx += configParam_.GetScreenWidth() * RGBA_CHROMA;
    }
    uint32_t jpegSize = CompressRgbaToJpeg(damage, partialBuffer, data);
    DHLOGI("EncodeDamageData jpegSize %." PRId32, jpegSize);
    delete [] partialBuffer;
}

int32_t JpegImageProcessor::DecodeDamageData(const std::shared_ptr<DataBuffer> &data, uint8_t *lastFrame)
{
    DHLOGI("%s: DecodeDamageData.", LOG_TAG);
    std::vector<DirtyRect> dirtyRectVec = data->GetDirtyRectVec();
    int32_t offset = 0;
    int32_t screenWidth = configParam_.GetScreenWidth();
    int32_t screenHeight = configParam_.GetScreenHeight();
    for (auto item : dirtyRectVec) {
        if (item.xPos > screenWidth || item.yPos > screenHeight ||
            item.width > screenWidth - item.xPos || item.height > screenHeight - item.yPos) {
            DHLOGE("%s: Dirty rect invalid.", LOG_TAG);
            return ERR_DH_SCREEN_INPUT_PARAM_INVALID;
        }
        uint8_t *jpegData = new uint8_t[item.dirtySize] {0};
        int32_t ret = data->GetData(offset, item.dirtySize, jpegData);
        if (ret != DH_SUCCESS) {
            delete [] jpegData;
            return ret;
        }
        offset += item.dirtySize;
        uint8_t *dirtyImageData = new uint8_t[item.width * item.height * RGB_CHROMA] {0};
        DHLOGI("%s: CompressRgbaToJpeg.", LOG_TAG);
        DecompressJpegToNV12(item.dirtySize, jpegData, dirtyImageData);
        DHLOGI("%s: DecompressJpegToNV12 success.", LOG_TAG);
        ret = ReplaceDamage2LastFrame(lastFrame, dirtyImageData, item);
        if (ret != DH_SUCCESS) {
            DHLOGE("ReplaceDamage2LastFrame failed, ret: %." PRId32, ret);
            delete [] jpegData;
            delete [] dirtyImageData;
            return ret;
        }
        delete [] jpegData;
        delete [] dirtyImageData;
    }
    DHLOGI("%s: DecodeDamageData success.", LOG_TAG);
    return DH_SUCCESS;
}

int32_t JpegImageProcessor::ReplaceDamage2LastFrame(uint8_t *lastFrame, uint8_t *dirtyImageData, const DirtyRect rect)
{
    DHLOGI("%s: ReplaceDamage2LastFrame.", LOG_TAG);
    uint8_t *lastFrameIdx = lastFrame;
    uint8_t *yData = lastFrameIdx + configParam_.GetScreenWidth() * rect.yPos + rect.xPos;
    uint8_t *uData = lastFrameIdx + configParam_.GetScreenWidth() * configParam_.GetScreenHeight() +
                configParam_.GetScreenWidth() * (rect.yPos / TWO) + rect.xPos;
    uint8_t *yDirtyData = dirtyImageData;
    uint8_t *uDirtyData = dirtyImageData + rect.width * rect.height;
    uint8_t *yTempData = nullptr;
    uint8_t *uTempData = nullptr;
    for (int32_t i = 0 ; i < rect.height ; i++) {
        yTempData = yData + i * configParam_.GetScreenWidth();
        int32_t ret = memcpy_s(yTempData, rect.width, yDirtyData, rect.width);
        if (ret != EOK) {
            DHLOGE("%s: memcpy yData failed.", LOG_TAG);
            return ret;
        }
        yDirtyData += rect.width;
        if (i % TWO) {
            uTempData = uData + configParam_.GetScreenWidth() * (i / TWO);
            ret = memcpy_s(uTempData, rect.width, uDirtyData, rect.width);
            if (ret != EOK) {
                DHLOGE("%s: memcpy uData failed.", LOG_TAG);
                return ret;
            }
            uDirtyData += rect.width;
            }
    }
    DHLOGI("%s: ReplaceDamage2LastFrame success.", LOG_TAG);
    return DH_SUCCESS;
}

uint32_t JpegImageProcessor::CompressRgbaToJpeg(const OHOS::Rect &damage,
    uint8_t *inputData, std::shared_ptr<DataBuffer> &data)
{
    jpeg_compress_struct cinfo;
    jpeg_error_mgr jerr;
    JSAMPROW row_pointer[1];

    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_compress(&cinfo);
    unsigned char *outBuffer = nullptr;
    unsigned long outSize = 0;
    jpeg_mem_dest(&cinfo, &outBuffer, &outSize);

    cinfo.image_width = damage.w;
    cinfo.image_height = damage.h;
    cinfo.input_components = RGB_CHROMA;
    cinfo.in_color_space = JCS_RGB;

    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, JPEG_QUALITY, TRUE);
    jpeg_start_compress(&cinfo, TRUE);
    unsigned char rgb_buffer[damage.w * RGB_CHROMA];
    unsigned char *pB = inputData;
    unsigned char *pG = inputData + 1;
    unsigned char *pR = inputData + TWO;
    while (cinfo.next_scanline < cinfo.image_height) {
        int index = 0;
        for (int i = 0 ; i < damage.w ; i++) {
            rgb_buffer[index++] = *pB;
            rgb_buffer[index++] = *pG;
            rgb_buffer[index++] = *pR;
            pB += RGBA_CHROMA;
            pG += RGBA_CHROMA;
            pR += RGBA_CHROMA;
        }
        row_pointer[0] = rgb_buffer;
        (void)jpeg_write_scanlines(&cinfo, row_pointer, 1);
    }
    jpeg_finish_compress(&cinfo);
    DirtyRect rect = {damage.x, damage.y, damage.w, damage.h, outSize};
    data->AddData(static_cast<size_t>(outSize), outBuffer);
    data->AddDirtyRect(rect);
    jpeg_destroy_compress(&cinfo);
    if (outBuffer != NULL) {
        free(outBuffer);
        outBuffer = NULL;
    }
    return (uint32_t)outSize;
}

void JpegImageProcessor::DecompressJpegToNV12(size_t jpegSize, uint8_t *inputData, uint8_t *outputData)
{
    jpeg_decompress_struct cinfo;
    jpeg_error_mgr jerr;
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, inputData, jpegSize);
    (void)jpeg_read_header(&cinfo, TRUE);
    (void)jpeg_start_decompress(&cinfo);
    int32_t row_stride = cinfo.output_width * cinfo.output_components;
    JSAMPARRAY buffer = (*cinfo.mem->alloc_sarray)((j_common_ptr)&cinfo, JPOOL_IMAGE, row_stride, 1);
    int32_t uvIndex = cinfo.output_width * cinfo.output_height;
    int32_t i = 0;
#ifdef LIBYUV
    uint8_t *rgb = new uint8_t[cinfo.output_width * cinfo.output_height * RGBA_CHROMA];
    int32_t rgbIndex = 0;
#else
    int32_t yIndex = 0;
#endif
    while (cinfo.output_scanline < cinfo.output_height) {
        (void)jpeg_read_scanlines(&cinfo, buffer, 1);
        for (int j = 0 ; j < cinfo.output_width ; j++) {
#ifdef LIBYUV
            rgb[rgbIndex++] = buffer[0][j * RGB_CHROMA + TWO];
            rgb[rgbIndex++] = buffer[0][j * RGB_CHROMA + 1];
            rgb[rgbIndex++] = buffer[0][j * RGB_CHROMA];
            rgb[rgbIndex++] = 0xff;
#else
            int32_t y = ((YR_PARAM * buffer[0][j * RGB_CHROMA] + YG_PARAM * buffer[0][j * RGB_CHROMA + 1] +
                YB_PARAM * buffer[0][j * RGB_CHROMA + TWO] + UA_PARAM) >> MOVEBITS) + YA_PARAM;
            int32_t u = ((UR_PARAM * buffer[0][j * RGB_CHROMA] - UG_PARAM * buffer[0][j * RGB_CHROMA + 1] +
                UB_PARAM * buffer[0][j * RGB_CHROMA + TWO] + UA_PARAM) >> MOVEBITS) + UA_PARAM;
            int32_t v = ((UB_PARAM * buffer[0][j * RGB_CHROMA] - VG_PARAM * buffer[0][j * RGB_CHROMA + 1] -
                VB_PARAM * buffer[0][j * RGB_CHROMA + TWO] + UA_PARAM) >> MOVEBITS) + UA_PARAM;
            outputData[yIndex++] = static_cast<uint8_t>((y < 0) ? 0 : (y > YUV_PARAM) ? YUV_PARAM : y);
            if ((i % TWO == 0) && (j % TWO == 0)) {
                outputData[uvIndex++] = static_cast<uint8_t>((u < 0) ? 0 : (u > YUV_PARAM) ? YUV_PARAM : u);
                outputData[uvIndex++] = static_cast<uint8_t>((v < 0) ? 0 : (v > YUV_PARAM) ? YUV_PARAM : v);
            }
#endif
        }
        ++i;
    }
    (void)jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);
#ifdef LIBYUV
    libyuv::ARGBToNV12(rgb, cinfo.output_width * RGBA_CHROMA, outputData, cinfo.output_width,
        outputData + uvIndex, cinfo.output_width, cinfo.output_width, cinfo.output_height);
    delete [] rgb;
#endif
}
} // namespace DistributedHardware
} // namespace OHOS