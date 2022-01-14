// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include "HAP+Internal.h"

HAP_RESULT_USE_CHECK
HAPError HAPDataCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPDataCharacteristic* characteristic,
        HAPError result,
        const void* valueBytes,
        size_t numValueBytes) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_Data);
    HAPPrecondition(result != kHAPError_InProgress);
    if (result == kHAPError_None) {
        HAPPrecondition(valueBytes);
    }

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseDataReadRequest(
                _server, session, accessory, service, characteristic, result, valueBytes, numValueBytes);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPBoolCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPBoolCharacteristic* characteristic,
        HAPError result,
        bool value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_Bool);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseBoolReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;      
}

HAP_RESULT_USE_CHECK
HAPError HAPUInt8CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt8Characteristic* characteristic,
        HAPError result,
        uint8_t value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_UInt8);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseUInt8ReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPUInt16CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt16Characteristic* characteristic,
        HAPError result,
        uint16_t value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_UInt16);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseUInt16ReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPUInt32CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt32Characteristic* characteristic,
        HAPError result,
        uint32_t value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_UInt32);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseUInt32ReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPUInt64CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt64Characteristic* characteristic,
        HAPError result,
        uint64_t value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_UInt64);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseUInt64ReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPIntCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPIntCharacteristic* characteristic,
        HAPError result,
        int32_t value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_Int);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseIntReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPFloatCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPFloatCharacteristic* characteristic,
        HAPError result,
        float value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_Float);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseFloatReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPStringCharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPStringCharacteristic* characteristic,
        HAPError result,
        const char* value) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_String);
    HAPPrecondition(result != kHAPError_InProgress);
    if (result == kHAPError_None) {
        HAPPrecondition(value);
    }

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseStringReadRequest(
                _server, session, accessory, service, characteristic, result, value);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPTLV8CharacteristicResponseReadRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPTLV8Characteristic* characteristic,
        HAPError result,
        HAPTLVWriterRef* writer) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(characteristic->format == kHAPCharacteristicFormat_TLV8);
    HAPPrecondition(result != kHAPError_InProgress);
    if (result == kHAPError_None) {
        HAPPrecondition(writer);
    }

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseTLV8ReadRequest(
                _server, session, accessory, service, characteristic, result, writer);
    }

    return kHAPError_Unknown;
}

HAP_RESULT_USE_CHECK
HAPError HAPCharacteristicResponseWriteRequest(
        HAPAccessoryServerRef* _server,
        HAPTransportType transportType,
        HAPSessionRef* session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPCharacteristic* characteristic,
        HAPError result) {
    HAPPrecondition(_server);
    HAPPrecondition(session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*)_server;
    HAPPrecondition((transportType == kHAPTransportType_IP && server->transports.ip) ||
        (transportType == kHAPTransportType_BLE && server->transports.ble));

    if (transportType == kHAPTransportType_IP) {
        return server->transports.ip->serverEngine.responseWriteRequest(
                _server, session, accessory, service, characteristic, result);
    }

    return kHAPError_Unknown;
}
