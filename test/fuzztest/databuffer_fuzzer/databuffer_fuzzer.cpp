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

#include "databuffer_fuzzer.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "data_buffer.h"
#include "dscreen_constants.h"
#include "fuzzer/FuzzedDataProvider.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr size_t MAX_BUFFER_CAPACITY = 4096;
constexpr size_t MAX_CHUNK_SIZE = 512;
constexpr uint8_t MAX_OPERATION_COUNT = 16;
constexpr uint8_t MAX_DIRTY_RECT_COUNT = 8;
constexpr uint32_t MAX_DIRTY_RECT_FIELD = 8192;

size_t ConsumeCapacity(FuzzedDataProvider &provider)
{
    return provider.ConsumeIntegralInRange<size_t>(0, MAX_BUFFER_CAPACITY);
}

void AddValidData(DataBuffer &buffer, FuzzedDataProvider &provider, size_t allocatedCapacity)
{
    if (allocatedCapacity == 0) {
        return;
    }

    size_t writeOffset = provider.ConsumeIntegralInRange<size_t>(0, allocatedCapacity - 1);
    size_t maxChunkSize = std::min(MAX_CHUNK_SIZE, allocatedCapacity - writeOffset);
    size_t chunkSize = provider.ConsumeIntegralInRange<size_t>(1, maxChunkSize);
    std::vector<unsigned char> chunk(chunkSize, 0);
    auto fuzzBytes = provider.ConsumeBytes<unsigned char>(chunkSize);
    std::copy(fuzzBytes.begin(), fuzzBytes.end(), chunk.begin());

    buffer.SetSize(writeOffset);
    unsigned char *inputData = chunk.data();
    buffer.AddData(chunk.size(), inputData);
}

void AddDirtyRects(DataBuffer &buffer, FuzzedDataProvider &provider)
{
    uint8_t rectCount = provider.ConsumeIntegralInRange<uint8_t>(0, MAX_DIRTY_RECT_COUNT);
    for (uint8_t index = 0; index < rectCount; ++index) {
        DirtyRect rect {
            provider.ConsumeIntegralInRange<uint32_t>(0, MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(0, MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(0, MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(0, MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(0, DSCREEN_MAX_LEN),
        };
        buffer.AddDirtyRect(rect);
    }
    (void)buffer.GetDirtyRectVec();
}

void ReadData(DataBuffer &buffer, FuzzedDataProvider &provider)
{
    size_t currentSize = buffer.Capacity();
    uint8_t mode = provider.ConsumeIntegralInRange<uint8_t>(0, 3);
    if (mode == 0) {
        uint8_t *output = nullptr;
        (void)buffer.GetData(0, 0, output);
        return;
    }

    if (mode == 1) {
        std::vector<uint8_t> output(1, 0);
        uint8_t *outputPtr = output.data();
        (void)buffer.GetData(-1, 0, outputPtr);
        return;
    }

    if (mode == 2 || currentSize == 0) {
        std::vector<uint8_t> output(1, 0);
        uint8_t *outputPtr = output.data();
        int32_t offset = static_cast<int32_t>(std::min<size_t>(currentSize + 1, MAX_BUFFER_CAPACITY));
        (void)buffer.GetData(offset, 1, outputPtr);
        return;
    }

    int32_t offset = provider.ConsumeIntegralInRange<int32_t>(0, static_cast<int32_t>(currentSize - 1));
    size_t remaining = currentSize - static_cast<size_t>(offset);
    int32_t dataSize = provider.ConsumeIntegralInRange<int32_t>(1,
        static_cast<int32_t>(std::min<size_t>(remaining, MAX_CHUNK_SIZE)));
    std::vector<uint8_t> output(static_cast<size_t>(dataSize), 0);
    uint8_t *outputPtr = output.data();
    (void)buffer.GetData(offset, dataSize, outputPtr);
}

void RunDataBufferOperation(DataBuffer &buffer, FuzzedDataProvider &provider, size_t &allocatedCapacity)
{
    uint8_t operation = provider.ConsumeIntegralInRange<uint8_t>(0, 5);
    switch (operation) {
        case 0: {
            size_t resetCapacity = ConsumeCapacity(provider);
            size_t currentSize = buffer.Capacity();
            buffer.ResetCapcity(resetCapacity);
            if (resetCapacity >= currentSize) {
                allocatedCapacity = buffer.Capacity();
            }
            break;
        }
        case 1:
            AddValidData(buffer, provider, allocatedCapacity);
            break;
        case 2: {
            unsigned char *inputData = nullptr;
            buffer.AddData(provider.ConsumeIntegralInRange<size_t>(0, MAX_CHUNK_SIZE), inputData);
            break;
        }
        case 3:
            ReadData(buffer, provider);
            break;
        case 4:
            AddDirtyRects(buffer, provider);
            break;
        default:
            buffer.SetDataType(provider.ConsumeIntegral<uint8_t>());
            (void)buffer.DataType();
            buffer.SetDataNumber(provider.ConsumeIntegralInRange<size_t>(0, DATA_QUEUE_MAX_SIZE));
            (void)buffer.DataNumber();
            break;
    }
}
} // namespace

void RunDatabufferFuzzer(FuzzedDataProvider &provider)
{
    size_t initialCapacity = ConsumeCapacity(provider);
    DataBuffer buffer(initialCapacity);
    size_t allocatedCapacity = buffer.Capacity();

    buffer.SetDataType(provider.ConsumeBool() ? VIDEO_FULL_SCREEN_DATA : VIDEO_PART_SCREEN_DATA);
    buffer.SetDataNumber(provider.ConsumeIntegralInRange<size_t>(0, DATA_QUEUE_MAX_SIZE));
    AddDirtyRects(buffer, provider);

    uint8_t operationCount = provider.ConsumeIntegralInRange<uint8_t>(1, MAX_OPERATION_COUNT);
    for (uint8_t index = 0; index < operationCount; ++index) {
        RunDataBufferOperation(buffer, provider, allocatedCapacity);
    }
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunDatabufferFuzzer(provider);
    return 0;
}
