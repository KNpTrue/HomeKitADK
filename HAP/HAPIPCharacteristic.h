// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#ifndef HAP_IP_CHARACTERISTIC_H
#define HAP_IP_CHARACTERISTIC_H

#ifdef __cplusplus
extern "C" {
#endif

#include "HAP+Internal.h"

#if __has_feature(nullability)
#pragma clang assume_nonnull begin
#endif

/**
 * Returns whether a characteristic supports HAP over IP (Ethernet / Wi-Fi).
 *
 * - Certain characteristics are only applicable to HAP over Bluetooth LE.
 *
 * @param      characteristic       Characteristic.
 *
 * @return true                     If the characteristic supports HAP over IP (Ethernet / Wi-Fi).
 * @return false                    Otherwise.
 */
HAP_RESULT_USE_CHECK
bool HAPIPCharacteristicIsSupported(const HAPCharacteristic* characteristic);

/**
 * Returns the number of enabled properties of a characteristic.
 *
 * @param      characteristic       Characteristic.
 *
 * @return Number of enabled properties.
 */
HAP_RESULT_USE_CHECK
size_t HAPCharacteristicGetNumEnabledProperties(const HAPCharacteristic* characteristic);

/**
 * Returns the unit of the characteristic value.
 *
 * @param      characteristic       Characteristic.
 *
 * @return Unit of the characteristic value.
 */
HAP_RESULT_USE_CHECK
HAPCharacteristicUnits HAPCharacteristicGetUnit(const HAPCharacteristic* characteristic);

void HAPIPCharacteristicContextSetDataValue(
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer,
        const void* valueBytes,
        size_t numValueBytes);

void HAPIPCharacteristicContextSetUIntValue(
        HAPIPCharacteristicContextRef* context,
        uint64_t value);

void HAPIPCharacteristicContextSetIntValue(
        HAPIPCharacteristicContextRef* context,
        int32_t value);

void HAPIPCharacteristicContextSetFloatValue(
        HAPIPCharacteristicContextRef* context,
        float value);

void HAPIPCharacteristicContextSetStringValue(
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer,
        const char* value);

void HAPIPCharacteristicContextSetTLV8Value(
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer,
        HAPTLVWriterRef* writer);

/**
 * Converts a characteristic read request error to the corresponding HAP status code.
 *
 * @param      error                Read request error.
 *
 * @return HAP read request status code.
 *
 * @see HomeKit Accessory Protocol Specification R14
 *      Table 6-11 HAP Status Codes
 */
HAP_RESULT_USE_CHECK
int32_t HAPIPCharacteristicConvertReadErrorToStatusCode(HAPError error);

/**
 * Converts a characteristic write request error to the corresponding HAP status code.
 *
 * @param      error                Write request error.
 *
 * @return HAP write request status code.
 *
 * @see HomeKit Accessory Protocol Specification R14
 *      Table 6-11 HAP Status Codes
 */
HAP_RESULT_USE_CHECK
int32_t HAPIPCharacteristicConvertWriteErrorToStatusCode(HAPError error);

void HAPIPCharacteristicHandleReadRequest(
        HAPIPSessionDescriptorRef* session,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory,
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer);

void HAPIPCharacteristicHandleWriteRequest(
        HAPIPSessionDescriptorRef* session,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory,
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer);

void HAPIPCharacteristicFinshWriteRequest(
        HAPIPSessionDescriptorRef* session,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory,
        HAPIPCharacteristicContextRef* context,
        HAPIPByteBuffer* dataBuffer);

void HAPIPCharacteristicHandleSubscribeRequest(
        HAPIPSessionDescriptorRef* session,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory);

void HAPIPCharacteristicHandleUnsubscribeRequest(
        HAPIPSessionDescriptorRef* session,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory);

#if __has_feature(nullability)
#pragma clang assume_nonnull end
#endif

#ifdef __cplusplus
}
#endif

#endif
