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

#include "screenhandlerstate_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include "dscreen_handler.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "ihardware_handler.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
#define SHSTATE_FUZZ_MAX_STRING_LENGTH (128)
#define SHSTATE_FUZZ_FUZZ_SUCCESS (0)
class FuzzPluginListener final : public PluginListener {
public:
    ~FuzzPluginListener() = default;

    void PluginHardware(const std::string &dhId, const std::string &attrs, const std::string &subtype) override
    {
        lastDhId_ = dhId;
        lastAttrs_ = attrs;
        lastSubtype_ = subtype;
    }

    void UnPluginHardware(const std::string &dhId) override
    {
        lastDhId_ = dhId;
    }

private:
    std::string lastDhId_;
    std::string lastAttrs_;
    std::string lastSubtype_;
};
} // namespace

void RunScreenhandlerstateFuzzer(FuzzedDataProvider &provider)
{
    std::string dhId = provider.ConsumeRandomLengthString(SHSTATE_FUZZ_MAX_STRING_LENGTH);
    std::string attr = provider.ConsumeRandomLengthString(SHSTATE_FUZZ_MAX_STRING_LENGTH);
    std::string subtype = provider.ConsumeBool() ? "screen" :
        provider.ConsumeRandomLengthString(SHSTATE_FUZZ_MAX_STRING_LENGTH);

    std::shared_ptr<PluginListener> listener = nullptr;
    if (provider.ConsumeBool()) {
        listener = std::make_shared<FuzzPluginListener>();
    }
    DScreenHandler::GetInstance().RegisterPluginListener(listener);
    DScreenHandler::GetInstance().PluginHardware(dhId, attr, subtype);
    DScreenHandler::GetInstance().UnPluginHardware(dhId);
    (void)DScreenHandler::GetInstance().IsSupportPlugin();
    (void)DScreenHandler::GetInstance().QueryMeta();
    (void)DScreenHandler::GetInstance().QueryExtraInfo();
    DScreenHandler::GetInstance().UnRegisterPluginListener();

    ScreenListener screenListener;
    (void)screenListener.ByteCalculate(provider.ConsumeIntegral<uint32_t>());
}
} // namespace DistributedHardware
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    OHOS::DistributedHardware::RunScreenhandlerstateFuzzer(provider);
    return SHSTATE_FUZZ_FUZZ_SUCCESS;
}
