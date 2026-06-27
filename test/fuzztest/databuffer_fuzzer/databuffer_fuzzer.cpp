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
#define DBUF_FUZZ_MAX_BUFFER_CAPACITY 4096
#define DBUF_FUZZ_MAX_CHUNK_SIZE 512
#define DBUF_FUZZ_MAX_OPERATION_COUNT 16
#define DBUF_FUZZ_MAX_DIRTY_RECT_COUNT 8
#define DBUF_FUZZ_MAX_DIRTY_RECT_FIELD 8192
#define DBUF_FUZZ_SIZE_ZERO 0
#define DBUF_FUZZ_SIZE_ONE 1
#define DBUF_FUZZ_INT_NEGATIVE_ONE -1
#define DBUF_FUZZ_INT_ZERO 0
#define DBUF_FUZZ_INT_ONE 1
#define DBUF_FUZZ_READ_MODE_NULL_OUTPUT 0
#define DBUF_FUZZ_READ_MODE_NEGATIVE_OFFSET 1
#define DBUF_FUZZ_READ_MODE_OUT_OF_RANGE_OFFSET 2
#define DBUF_FUZZ_MAX_READ_MODE 3
#define DBUF_FUZZ_OPERATION_RESET_CAPACITY 0
#define DBUF_FUZZ_OPERATION_ADD_VALID_DATA 1
#define DBUF_FUZZ_OPERATION_ADD_NULL_DATA 2
#define DBUF_FUZZ_OPERATION_READ_DATA 3
#define DBUF_FUZZ_OPERATION_ADD_DIRTY_RECTS 4
#define DBUF_FUZZ_MAX_OPERATION_KIND 5
#define DBUF_FUZZ_FUZZ_SUCCESS 0
size_t ConsumeCapacity(FuzzedDataProvider &provider)
{
    return provider.ConsumeIntegralInRange<size_t>(DBUF_FUZZ_SIZE_ZERO, DBUF_FUZZ_MAX_BUFFER_CAPACITY);
}

void AddValidData(DataBuffer &buffer, FuzzedDataProvider &provider, size_t allocatedCapacity)
{
    if (allocatedCapacity == DBUF_FUZZ_SIZE_ZERO) {
        return;
    }

    size_t writeOffset = provider.ConsumeIntegralInRange<size_t>(DBUF_FUZZ_SIZE_ZERO,
        allocatedCapacity - DBUF_FUZZ_SIZE_ONE);
    size_t maxChunkSize = std::min(DBUF_FUZZ_MAX_CHUNK_SIZE, allocatedCapacity - writeOffset);
    size_t chunkSize = provider.ConsumeIntegralInRange<size_t>(DBUF_FUZZ_SIZE_ONE, maxChunkSize);
    std::vector<unsigned char> chunk(chunkSize, DBUF_FUZZ_SIZE_ZERO);
    auto fuzzBytes = provider.ConsumeBytes<unsigned char>(chunkSize);
    std::copy(fuzzBytes.begin(), fuzzBytes.end(), chunk.begin());

    buffer.SetSize(writeOffset);
    unsigned char *inputData = chunk.data();
    buffer.AddData(chunk.size(), inputData);
}

void AddDirtyRects(DataBuffer &buffer, FuzzedDataProvider &provider)
{
    uint8_t rectCount = provider.ConsumeIntegralInRange<uint8_t>(DBUF_FUZZ_READ_MODE_NULL_OUTPUT,
        DBUF_FUZZ_MAX_DIRTY_RECT_COUNT);
    for (uint8_t index = DBUF_FUZZ_READ_MODE_NULL_OUTPUT; index < rectCount; ++index) {
        DirtyRect rect {
            provider.ConsumeIntegralInRange<uint32_t>(DBUF_FUZZ_INT_ZERO, DBUF_FUZZ_MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(DBUF_FUZZ_INT_ZERO, DBUF_FUZZ_MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(DBUF_FUZZ_INT_ZERO, DBUF_FUZZ_MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(DBUF_FUZZ_INT_ZERO, DBUF_FUZZ_MAX_DIRTY_RECT_FIELD),
            provider.ConsumeIntegralInRange<uint32_t>(DBUF_FUZZ_INT_ZERO, DSCREEN_MAX_LEN),
        };
        buffer.AddDirtyRect(rect);
    }
    (void)buffer.GetDirtyRectVec();
}

void ReadData(DataBuffer &buffer, FuzzedDataProvider &provider)
{
    size_t currentSize = buffer.Capacity();
    uint8_t mode = provider.ConsumeIntegralInRange<uint8_t>(DBUF_FUZZ_READ_MODE_NULL_OUTPUT, DBUF_FUZZ_MAX_READ_MODE);
    if (mode == DBUF_FUZZ_READ_MODE_NULL_OUTPUT) {
        uint8_t *output = nullptr;
        (void)buffer.GetData(DBUF_FUZZ_INT_ZERO, DBUF_FUZZ_INT_ZERO, output);
        return;
    }

    if (mode == DBUF_FUZZ_READ_MODE_NEGATIVE_OFFSET) {
        std::vector<uint8_t> output(DBUF_FUZZ_SIZE_ONE, DBUF_FUZZ_SIZE_ZERO);
        uint8_t *outputPtr = output.data();
        (void)buffer.GetData(DBUF_FUZZ_INT_NEGATIVE_ONE, DBUF_FUZZ_INT_ZERO, outputPtr);
        return;
    }

    if (mode == DBUF_FUZZ_READ_MODE_OUT_OF_RANGE_OFFSET || currentSize == DBUF_FUZZ_SIZE_ZERO) {
        std::vector<uint8_t> output(DBUF_FUZZ_SIZE_ONE, DBUF_FUZZ_SIZE_ZERO);
        uint8_t *outputPtr = output.data();
        size_t nextOffset = currentSize + DBUF_FUZZ_SIZE_ONE;
        int32_t offset = static_cast<int32_t>(std::min<size_t>(nextOffset, DBUF_FUZZ_MAX_BUFFER_CAPACITY));
        (void)buffer.GetData(offset, DBUF_FUZZ_INT_ONE, outputPtr);
        return;
    }

    int32_t offset = provider.ConsumeIntegralInRange<int32_t>(DBUF_FUZZ_INT_ZERO,
        static_cast<int32_t>(currentSize - DBUF_FUZZ_SIZE_ONE));
    size_t remaining = currentSize - static_cast<size_t>(offset);
    int32_t dataSize = provider.ConsumeIntegralInRange<int32_t>(DBUF_FUZZ_INT_ONE,
        static_cast<int32_t>(std::min<size_t>(remaining, DBUF_FUZZ_MAX_CHUNK_SIZE)));
    std::vector<uint8_t> output(static_cast<size_t>(dataSize), DBUF_FUZZ_SIZE_ZERO);
    uint8_t *outputPtr = output.data();
    (void)buffer.GetData(offset, dataSize, outputPtr);
}

void RunDataBufferOperation(DataBuffer &buffer, FuzzedDataProvider &provider, size_t &allocatedCapacity)
{
    uint8_t operation = provider.ConsumeIntegralInRange<uint8_t>(DBUF_FUZZ_OPERATION_RESET_CAPACITY,
        DBUF_FUZZ_MAX_OPERATION_KIND);
    switch (operation) {
        case DBUF_FUZZ_OPERATION_RESET_CAPACITY: {
            size_t resetCapacity = ConsumeCapacity(provider);
            size_t currentSize = buffer.Capacity();
            buffer.ResetCapcity(resetCapacity);
            if (resetCapacity >= currentSize) {
                allocatedCapacity = buffer.Capacity();
            }
            break;
        }
        case DBUF_FUZZ_OPERATION_ADD_VALID_DATA:
            AddValidData(buffer, provider, allocatedCapacity);
            break;
        case DBUF_FUZZ_OPERATION_ADD_NULL_DATA: {
            unsigned char *inputData = nullptr;
            size_t dataSize = provider.ConsumeIntegralInRange<size_t>(DBUF_FUZZ_SIZE_ZERO,
                DBUF_FUZZ_MAX_CHUNK_SIZE);
            buffer.AddData(dataSize, inputData);
            break;
        }
        case DBUF_FUZZ_OPERATION_READ_DATA:
            ReadData(buffer, provider);
            break;
        case DBUF_FUZZ_OPERATION_ADD_DIRTY_RECTS:
            AddDirtyRects(buffer, provider);
            break;
        default:
            buffer.SetDataType(provider.ConsumeIntegral<uint8_t>());
            (void)buffer.DataType();
            buffer.SetDataNumber(provider.ConsumeIntegralInRange<size_t>(DBUF_FUZZ_SIZE_ZERO, DATA_QUEUE_MAX_SIZE));
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
    buffer.SetDataNumber(provider.ConsumeIntegralInRange<size_t>(DBUF_FUZZ_SIZE_ZERO, DATA_QUEUE_MAX_SIZE));
    AddDirtyRects(buffer, provider);

    uint8_t operationCount = provider.ConsumeIntegralInRange<uint8_t>(DBUF_FUZZ_READ_MODE_NEGATIVE_OFFSET,
        DBUF_FUZZ_MAX_OPERATION_COUNT);
    for (uint8_t index = DBUF_FUZZ_READ_MODE_NULL_OUTPUT; index < operationCount; ++index) {
        RunDataBufferOperation(buffer, provider, allocatedCapacity);
    }
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunDatabufferFuzzer(provider);
    return DBUF_FUZZ_FUZZ_SUCCESS;
}
