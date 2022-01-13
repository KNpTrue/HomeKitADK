// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#ifndef HAP_CHARACTERISTIC_RESPONSE_H
#define HAP_CHARACTERISTIC_RESPONSE_H

#include <HAP.h>

#ifdef __cplusplus
extern "C" {
#endif

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

HAP_RESULT_USE_CHECK
HAPError HAPDataCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPDataCharacteristic* characteristic,
        HAPError result,
        const void* valueBytes,
        size_t numValueBytes);

HAP_RESULT_USE_CHECK
HAPError HAPBoolCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPBoolCharacteristic* characteristic,
        HAPError result,
        bool value);

HAP_RESULT_USE_CHECK
HAPError HAPUInt8CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt8Characteristic* characteristic,
        HAPError result,
        uint8_t value);

HAP_RESULT_USE_CHECK
HAPError HAPUInt16CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt16Characteristic* characteristic,
        HAPError result,
        uint16_t value);

HAP_RESULT_USE_CHECK
HAPError HAPUInt32CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt32Characteristic* characteristic,
        HAPError result,
        uint32_t value);

HAP_RESULT_USE_CHECK
HAPError HAPUInt64CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt64Characteristic* characteristic,
        HAPError result,
        uint64_t value);

HAP_RESULT_USE_CHECK
HAPError HAPIntCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPIntCharacteristic* characteristic,
        HAPError result,
        int32_t value);

HAP_RESULT_USE_CHECK
HAPError HAPFloatCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPFloatCharacteristic* characteristic,
        HAPError result,
        float value);

HAP_RESULT_USE_CHECK
HAPError HAPStringCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPStringCharacteristic* characteristic,
        HAPError result,
        const char* value);

HAP_RESULT_USE_CHECK
HAPError HAPTLV8CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPTLV8Characteristic* characteristic,
        HAPError result,
        HAPTLVWriterRef* writer);

HAP_RESULT_USE_CHECK
HAPError HAPCharacteristicResponseWriteRequest(
        HAPAccessoryServerRef* server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPCharacteristic* characteristic,
        HAPError result);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
