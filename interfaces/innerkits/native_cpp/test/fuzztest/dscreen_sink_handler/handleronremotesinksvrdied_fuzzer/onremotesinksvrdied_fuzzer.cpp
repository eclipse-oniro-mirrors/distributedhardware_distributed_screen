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

#include <cstddef>
#include <cstdint>

#include "onremotesinksvrdied_fuzzer.h"
#include "dscreen_sink_handler.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"

namespace OHOS {
namespace DistributedHardware {
void OnRemoteSinkSvrDiedFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider dataProvider(data, size);
    int32_t saId = dataProvider.ConsumeIntegral<int32_t>();

    sptr<ISystemAbilityManager> samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        return;
    }

    sptr<IRemoteObject> remoteObject = samgr->GetSystemAbility(saId);
    if (remoteObject == nullptr) {
        return;
    }
    wptr<IRemoteObject> remote(remoteObject);

    DScreenSinkHandler::GetInstance().OnRemoteSinkSvrDied(remote);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::OnRemoteSinkSvrDiedFuzzTest(data, size);
    return 0;
}
