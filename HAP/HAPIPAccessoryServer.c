// Copyright (c) 2015-2019 The HomeKit ADK Contributors
//
// Licensed under the Apache License, Version 2.0 (the “License”);
// you may not use this file except in compliance with the License.
// See [CONTRIBUTORS.md] for the list of HomeKit ADK project authors.

#include "HAP+Internal.h"

#if HAP_IP

#include "util_base64.h"

static const HAPLogObject logObject = { .subsystem = kHAP_LogSubsystem, .category = "IPAccessoryServer" };

/** Build-time flag to disable session security. */
#define kHAPIPAccessoryServer_SessionSecurityDisabled ((bool) false)

/** US-ASCII horizontal-tab character. */
#define kHAPIPAccessoryServerCharacter_HorizontalTab ((char) 9)

/** US-ASCII space character. */
#define kHAPIPAccessoryServerCharacter_Space ((char) 32)

/**
 * Predefined HTTP/1.1 response indicating successful request completion with an empty response body.
 */
#define kHAPIPAccessoryServerResponse_NoContent ("HTTP/1.1 204 No Content\r\n\r\n")

/**
 * Predefined HTTP/1.1 response indicating a malformed request.
 */
#define kHAPIPAccessoryServerResponse_BadRequest \
    ("HTTP/1.1 400 Bad Request\r\n" \
     "Content-Length: 0\r\n\r\n")

/**
 * Predefined HTTP/1.1 response indicating that the client has insufficient privileges to request the corresponding
 * operation.
 */
#define kHAPIPAccessoryServerResponse_InsufficientPrivileges \
    ("HTTP/1.1 400 Bad Request\r\n" \
     "Content-Type: application/hap+json\r\n" \
     "Content-Length: 17\r\n\r\n" \
     "{\"status\":-70401}")

/**
 * Predefined HTTP/1.1 response indicating that the requested resource is not available.
 */
#define kHAPIPAccessoryServerResponse_ResourceNotFound \
    ("HTTP/1.1 404 Not Found\r\n" \
     "Content-Length: 0\r\n\r\n")

/**
 * Predefined HTTP/1.1 response indicating that the requested operation is not supported for the requested resource.
 */
#define kHAPIPAccessoryServerResponse_MethodNotAllowed \
    ("HTTP/1.1 405 Method Not Allowed\r\n" \
     "Content-Length: 0\r\n\r\n")

/**
 * Predefined HTTP/1.1 response indicating that the connection is not authorized to request the corresponding operation.
 */
#define kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired \
    ("HTTP/1.1 470 Connection Authorization Required\r\n" \
     "Content-Length: 0\r\n\r\n")

/**
 * Predefined HTTP/1.1 response indicating that the connection is not authorized to request the corresponding operation,
 * including a HAP status code.
 */
#define kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequiredWithStatus \
    ("HTTP/1.1 470 Connection Authorization Required\r\n" \
     "Content-Type: application/hap+json\r\n" \
     "Content-Length: 17\r\n\r\n" \
     "{\"status\":-70411}")

/**
 * Predefined HTTP/1.1 response indicating that the server encountered an unexpected condition which prevented it from
 * successfully processing the request.
 */
#define kHAPIPAccessoryServerResponse_InternalServerError \
    ("HTTP/1.1 500 Internal Server Error\r\n" \
     "Content-Length: 0\r\n\r\n")

/**
 * Predefined HTTP/1.1 response indicating that the server did not have enough resources to process request.
 */
#define kHAPIPAccessoryServerResponse_OutOfResources \
    ("HTTP/1.1 500 Internal Server Error\r\n" \
     "Content-Type: application/hap+json\r\n" \
     "Content-Length: 17\r\n\r\n" \
     "{\"status\":-70407}")

/**
 * Maximum time an IP session can stay idle before it will be closed by the accessory server.
 *
 * - Maximum idle time will on be enforced during shutdown of the accessory server or at maximum capacity.
 */
#define kHAPIPSession_MaxIdleTime ((HAPTime)(60 * HAPSecond))

/**
 * Maximum delay during which event notifications will be coalesced into a single message.
 */
#define kHAPIPAccessoryServer_MaxEventNotificationDelay ((HAPTime)(1 * HAPSecond))

/**
 * Timeout for every event notifications progress.
 */
#define kHAPIPAccessoryServer_EventNotificationTimeout ((HAPTime)(5 * HAPSecond))

static void HandleTCPStreamEvent(
        HAPPlatformTCPStreamManagerRef tcpStreamManager,
        HAPPlatformTCPStreamRef tcpStream,
        HAPPlatformTCPStreamEvent event,
        void* _Nullable context);

static void log_result(HAPLogType type, char* msg, int result, const char* function, const char* file, int line) {
    HAPAssert(msg);
    HAPAssert(function);
    HAPAssert(file);

    HAPLogWithType(&logObject, type, "%s:%d - %s @ %s:%d", msg, result, function, file, line);
}

static void log_protocol_error(
        HAPLogType type,
        char* msg,
        HAPIPByteBuffer* b,
        const char* function,
        const char* file,
        int line) {
    HAPAssert(msg);
    HAPAssert(b);
    HAPAssert(function);
    HAPAssert(file);

    HAPLogBufferWithType(
            &logObject,
            b->data,
            b->position,
            type,
            "%s:%lu - %s @ %s:%d",
            msg,
            (unsigned long) b->position,
            function,
            file,
            line);
}

static void get_db_ctx(
        HAPAccessoryServerRef* server_,
        uint64_t aid,
        uint64_t iid,
        const HAPCharacteristic** chr,
        const HAPService** svc,
        const HAPAccessory** acc) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;
    HAPPrecondition(chr);
    HAPPrecondition(svc);
    HAPPrecondition(acc);

    *chr = NULL;
    *svc = NULL;
    *acc = NULL;

    const HAPAccessory* accessory = NULL;

    if (server->primaryAccessory->aid == aid) {
        accessory = server->primaryAccessory;
    } else if (server->ip.bridgedAccessories) {
        for (size_t i = 0; server->ip.bridgedAccessories[i]; i++) {
            if (server->ip.bridgedAccessories[i]->aid == aid) {
                accessory = server->ip.bridgedAccessories[i];
                break;
            }
        }
    }

    if (accessory) {
        size_t i = 0;
        while (accessory->services[i] && !*chr) {
            const HAPService* service = accessory->services[i];
            if (HAPAccessoryServerSupportsService(server_, kHAPTransportType_IP, service)) {
                size_t j = 0;
                while (service->characteristics[j] && !*chr) {
                    const HAPBaseCharacteristic* characteristic = service->characteristics[j];
                    if (HAPIPCharacteristicIsSupported(characteristic)) {
                        if (characteristic->iid == iid) {
                            *chr = characteristic;
                            *svc = service;
                            *acc = accessory;
                        } else {
                            j++;
                        }
                    } else {
                        j++;
                    }
                }
                if (!*chr) {
                    i++;
                }
            } else {
                i++;
            }
        }
    }
}

static HAPIPCharacteristicContext* get_ctx_by_iid(
        size_t aid,
        size_t iid,
        HAPIPCharacteristicContextRef* contexts,
        size_t numContexts) {
    for (size_t i = 0; i < numContexts; i++) {
        HAPIPCharacteristicContext* context = (HAPIPCharacteristicContext*) &contexts[i];
        if (context->aid == aid && context->iid == iid) {
            return context;
        }
    }
    return NULL;
}

static void publish_homeKit_service(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    HAPAssert(!server->ip.isServiceDiscoverable);
    HAPAssert(HAPPlatformTCPStreamManagerIsListenerOpen(HAPNonnull(server->platform.ip.tcpStreamManager)));

    HAPIPServiceDiscoverySetHAPService(server_);
    server->ip.isServiceDiscoverable = true;
}

static void HandlePendingTCPStream(HAPPlatformTCPStreamManagerRef tcpStreamManager, void* _Nullable context);

static void schedule_max_idle_time_timer(HAPAccessoryServerRef* server_);

static void HAPIPSessionReset(HAPIPSession* ipSession) {
    HAPPrecondition(ipSession);
    HAPPrecondition(ipSession->inboundBuffer.bytes);
    HAPPrecondition(ipSession->outboundBuffer.bytes);
    HAPPrecondition(ipSession->scratchBuffer.bytes);
    HAPPrecondition(ipSession->eventNotifications);
    HAPPrecondition(ipSession->contexts);

    HAPRawBufferZero(&ipSession->descriptor, sizeof(ipSession->descriptor));
    HAPRawBufferZero(ipSession->inboundBuffer.bytes, ipSession->inboundBuffer.numBytes);
    HAPRawBufferZero(ipSession->outboundBuffer.bytes, ipSession->outboundBuffer.numBytes);
    HAPRawBufferZero(ipSession->scratchBuffer.bytes, ipSession->scratchBuffer.numBytes);
    HAPRawBufferZero(ipSession->contexts, ipSession->numContexts * sizeof(*ipSession->contexts));
    HAPRawBufferZero(ipSession->eventNotifications,
        ipSession->numEventNotifications * sizeof(*ipSession->eventNotifications));
}

static void collect_garbage(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    if (server->ip.garbageCollectionTimer) {
        HAPPlatformTimerDeregister(server->ip.garbageCollectionTimer);
        server->ip.garbageCollectionTimer = 0;
    }

    size_t n = 0;
    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
        HAPIPSession* ipSession = &server->ip.storage->sessions[i];
        HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) &ipSession->descriptor;
        if (!session->server) {
            continue;
        }

        if (session->state == kHAPIPSessionState_Idle) {
            HAPIPSessionReset(ipSession);
            HAPLogDebug(&logObject, "session:%p:released", (const void*) session);
            HAPAssert(server->ip.numSessions > 0);
            server->ip.numSessions--;
        } else {
            n++;
        }
    }
    HAPAssert(n == server->ip.numSessions);

    // If there are open sessions, wait until they are closed before continuing.
    if (HAPPlatformTCPStreamManagerIsListenerOpen(HAPNonnull(server->platform.ip.tcpStreamManager)) ||
        (server->ip.numSessions != 0)) {
        return;
    }

    // Finalize server state transition after last session closed.
    HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Stopping);
    if (server->ip.stateTransitionTimer) {
        HAPPlatformTimerDeregister(server->ip.stateTransitionTimer);
        server->ip.stateTransitionTimer = 0;
    }
    if (server->ip.maxIdleTimeTimer) {
        HAPPlatformTimerDeregister(server->ip.maxIdleTimeTimer);
        server->ip.maxIdleTimeTimer = 0;
    }
    HAPLogDebug(&logObject, "Completing accessory server state transition.");
    if (server->ip.nextState == kHAPIPAccessoryServerState_Running) {
        server->ip.state = kHAPIPAccessoryServerState_Running;
        server->ip.nextState = kHAPIPAccessoryServerState_Undefined;
        HAPAccessoryServerDelegateScheduleHandleUpdatedState(server_);
    } else {
        HAPAssert(server->ip.nextState == kHAPIPAccessoryServerState_Idle);

        // HAPAccessoryServerStop.

        if (server->ip.isServiceDiscoverable) {
            HAPIPServiceDiscoveryStop(server_);
            server->ip.isServiceDiscoverable = false;
        }

        // Stop service discovery.
        if (server->ip.discoverableService) {
            HAPAssert(!server->ip.isServiceDiscoverable);
            HAPAssert(server->ip.discoverableService == kHAPIPServiceDiscoveryType_HAP);
            HAPIPServiceDiscoveryStop(server_);
        }

        HAPAssert(!server->ip.discoverableService);
        HAPAssert(!server->ip.isServiceDiscoverable);

        server->ip.state = kHAPIPAccessoryServerState_Idle;
        server->ip.nextState = kHAPIPAccessoryServerState_Undefined;
        HAPAccessoryServerDelegateScheduleHandleUpdatedState(server_);
    }
}

static void handle_garbage_collection_timer(HAPPlatformTimerRef timer, void* _Nullable context) {
    HAPPrecondition(context);
    HAPAccessoryServerRef* server_ = context;
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;
    (void) server;
    HAPPrecondition(timer == server->ip.garbageCollectionTimer);
    server->ip.garbageCollectionTimer = 0;

    collect_garbage(server_);
}

static void handle_max_idle_time_timer(HAPPlatformTimerRef timer, void* _Nullable context) {
    HAPPrecondition(context);
    HAPAccessoryServerRef* server_ = context;
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;
    (void) server;
    HAPPrecondition(timer == server->ip.maxIdleTimeTimer);
    server->ip.maxIdleTimeTimer = 0;

    HAPLogDebug(&logObject, "Session idle timer expired.");
    schedule_max_idle_time_timer(server_);
}

static void CloseSession(HAPIPSessionDescriptor* session);

static void schedule_max_idle_time_timer(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    if (server->ip.maxIdleTimeTimer) {
        HAPPlatformTimerDeregister(server->ip.maxIdleTimeTimer);
        server->ip.maxIdleTimeTimer = 0;
    }

    HAPError err;

    HAPTime clock_now_ms = HAPPlatformClockGetCurrent();

    int64_t timeout_ms = -1;

    if ((server->ip.state == kHAPIPAccessoryServerState_Stopping) &&
        HAPPlatformTCPStreamManagerIsListenerOpen(HAPNonnull(server->platform.ip.tcpStreamManager))) {
        HAPPlatformTCPStreamManagerCloseListener(HAPNonnull(server->platform.ip.tcpStreamManager));
    }

    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
        HAPIPSession* ipSession = &server->ip.storage->sessions[i];
        HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) &ipSession->descriptor;
        if (!session->server) {
            continue;
        }

        if ((session->state == kHAPIPSessionState_Reading) && (session->inboundBuffer.position == 0) &&
            (server->ip.state == kHAPIPAccessoryServerState_Stopping)) {
            CloseSession(session);
        } else if (
                ((session->state == kHAPIPSessionState_Reading) || (session->state == kHAPIPSessionState_Writing)) &&
                ((server->ip.numSessions == server->ip.storage->numSessions) ||
                 (server->ip.state == kHAPIPAccessoryServerState_Stopping))) {
            HAPAssert(clock_now_ms >= session->stamp);
            HAPTime dt_ms = clock_now_ms - session->stamp;
            if (dt_ms < kHAPIPSession_MaxIdleTime) {
                HAPAssert(kHAPIPSession_MaxIdleTime <= INT64_MAX);
                int64_t t_ms = (int64_t)(kHAPIPSession_MaxIdleTime - dt_ms);
                if ((timeout_ms == -1) || (t_ms < timeout_ms)) {
                    timeout_ms = t_ms;
                }
            } else {
                HAPLogInfo(&logObject, "Connection timeout.");
                CloseSession(session);
            }
        }
    }

    if (timeout_ms >= 0) {
        HAPTime deadline_ms;

        if (UINT64_MAX - clock_now_ms < (HAPTime) timeout_ms) {
            HAPLog(&logObject, "Clipping maximum idle time timer to avoid clock overflow.");
            deadline_ms = UINT64_MAX;
        } else {
            deadline_ms = clock_now_ms + (HAPTime) timeout_ms;
        }
        HAPAssert(deadline_ms >= clock_now_ms);

        err = HAPPlatformTimerRegister(&server->ip.maxIdleTimeTimer, deadline_ms, handle_max_idle_time_timer, server_);
        if (err) {
            HAPLog(&logObject, "Not enough resources to schedule maximum idle time timer!");
            HAPFatalError();
        }
        HAPAssert(server->ip.maxIdleTimeTimer);
    }

    if (!server->ip.garbageCollectionTimer) {
        err = HAPPlatformTimerRegister(&server->ip.garbageCollectionTimer, 0, handle_garbage_collection_timer, server_);
        if (err) {
            HAPLog(&logObject, "Not enough resources to schedule garbage collection!");
            HAPFatalError();
        }
        HAPAssert(server->ip.garbageCollectionTimer);
    }
}

static void RegisterSession(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(server->ip.numSessions < server->ip.storage->numSessions);

    server->ip.numSessions++;
    if (server->ip.numSessions == server->ip.storage->numSessions) {
        schedule_max_idle_time_timer(session->server);
    }
}

static void CloseSession(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;

    HAPAssert(session->state != kHAPIPSessionState_Idle);

    HAPError err;

    HAPLogDebug(&logObject, "session:%p:closing", (const void*) session);

    while (session->numEventNotifications) {
        HAPIPEventNotification* eventNotification =
                (HAPIPEventNotification*) &session->eventNotifications[session->numEventNotifications - 1];
        const HAPCharacteristic* characteristic;
        const HAPService* service;
        const HAPAccessory* accessory;
        get_db_ctx(
                session->server, eventNotification->aid, eventNotification->iid, &characteristic, &service, &accessory);
        if (eventNotification->flag) {
            HAPAssert(session->numEventNotificationFlags);
            session->numEventNotificationFlags--;
        }
        session->numEventNotifications--;
        HAPIPCharacteristicHandleUnsubscribeRequest((HAPIPSessionDescriptorRef*) session, characteristic, service, accessory);
    }
    if (session->inProgress.state != kHAPIPSessionInProgressState_None) {
        session->inProgress.state = kHAPIPSessionInProgressState_None;
        session->inProgress.numContexts = 0;
        if (session->inProgress.timer) {
            HAPPlatformTimerDeregister(session->inProgress.timer);
            session->inProgress.timer = 0;
        }
    }
    if (session->securitySession.isOpen) {
        HAPLogDebug(&logObject, "session:%p:closing security context", (const void*) session);
        HAPLogDebug(&logObject, "Closing HAP session.");
        HAPSessionRelease(HAPNonnull(session->server), &session->securitySession.session);
        HAPRawBufferZero(&session->securitySession, sizeof session->securitySession);
        HAPAssert(!session->securitySession.isSecured);
        HAPAssert(!session->securitySession.isOpen);
    }
    if (session->tcpStreamIsOpen) {
        HAPLogDebug(&logObject, "session:%p:closing TCP stream", (const void*) session);
        HAPPlatformTCPStreamClose(HAPNonnull(server->platform.ip.tcpStreamManager), session->tcpStream);
        session->tcpStreamIsOpen = false;
    }
    session->state = kHAPIPSessionState_Idle;
    if (!server->ip.garbageCollectionTimer) {
        err = HAPPlatformTimerRegister(
                &server->ip.garbageCollectionTimer, 0, handle_garbage_collection_timer, session->server);
        if (err) {
            HAPLog(&logObject, "Not enough resources to schedule garbage collection!");
            HAPFatalError();
        }
        HAPAssert(server->ip.garbageCollectionTimer);
    }

    HAPLogDebug(&logObject, "session:%p:closed", (const void*) session);
}

static void OpenSecuritySession(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(!session->securitySession.isOpen);
    HAPPrecondition(!session->securitySession.isSecured);

    HAPLogDebug(&logObject, "Opening HAP session.");
    HAPSessionCreate(HAPNonnull(session->server), &session->securitySession.session, kHAPTransportType_IP);

    session->securitySession.isOpen = true;
}

static void write_msg(HAPIPByteBuffer* b, const char* msg) {
    HAPError err;

    err = HAPIPByteBufferAppendStringWithFormat(b, "%s", msg);
    HAPAssert(!err);
}

static void prepare_reading_request(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);

    util_http_reader_init(&session->httpReader, util_HTTP_READER_TYPE_REQUEST);
    session->httpReaderPosition = 0;
    session->httpParserError = false;
    session->httpMethod.bytes = NULL;
    session->httpURI.bytes = NULL;
    session->httpHeaderFieldName.bytes = NULL;
    session->httpHeaderFieldValue.bytes = NULL;
    session->httpContentLength.isDefined = false;
    session->httpContentType = kHAPIPAccessoryServerContentType_Unknown;
}

static void handle_input(HAPIPSessionDescriptor* session);

static void post_resource(HAPIPSessionDescriptor* session HAP_UNUSED) {
}

static void put_prepare(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));

    HAPError err;
    uint64_t ttl, pid;

    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->httpReaderPosition <= session->inboundBuffer.position);
    if (session->httpContentLength.isDefined) {
        HAPAssert(session->httpContentLength.value <= session->inboundBuffer.position - session->httpReaderPosition);
        err = HAPIPAccessoryProtocolGetCharacteristicWritePreparation(
                &session->inboundBuffer.data[session->httpReaderPosition],
                session->httpContentLength.value,
                &ttl,
                &pid);
        if (!err) {
            HAPLogDebug(&logObject, "Prepare Write Request - TTL = %lu ms.", (unsigned long) ttl);

            // If the accessory receives consecutive Prepare Write Requests in the same session, the accessory must
            // reset the timed write transaction with the TTL specified by the latest request.
            // See HomeKit Accessory Protocol Specification R14
            // Section 6.7.2.4 Timed Write Procedures
            // Assumption: Same behavior for PID.

            // TTL.
            HAPTime clock_now_ms = HAPPlatformClockGetCurrent();
            if (UINT64_MAX - clock_now_ms < ttl) {
                HAPLog(&logObject, "Clipping TTL to avoid clock overflow.");
                session->timedWriteExpirationTime = UINT64_MAX;
            } else {
                session->timedWriteExpirationTime = clock_now_ms + ttl;
            }
            HAPAssert(session->timedWriteExpirationTime >= clock_now_ms);

            // PID.
            session->timedWritePID = pid;

            // The accessory must respond with a 200 OK HTTP Status Code and include a HAP status code indicating if
            // timed write procedure can be executed or not.
            // See HomeKit Accessory Protocol Specification R14
            // Section 6.7.2.4 Timed Write Procedures
            // It is not documented under what conditions this should fail.
            write_msg(
                    &session->outboundBuffer,
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/hap+json\r\n"
                    "Content-Length: 12\r\n\r\n"
                    "{\"status\":0}");
        } else {
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
        }
    } else {
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
    }
}

static void write_characteristic_write_response(
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContextRef* contexts,
        size_t contexts_count) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));

    HAPError err;
    size_t content_length, mark;

    HAPAssert(contexts);
    HAPAssert(session->outboundBuffer.data);
    HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
    HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);
    content_length = HAPIPAccessoryProtocolGetNumCharacteristicWriteResponseBytes(
            HAPNonnull(session->server), contexts, contexts_count);
    HAP_DIAGNOSTIC_IGNORED_ICCARM(Pa084)
    if (content_length <= UINT32_MAX) {
        mark = session->outboundBuffer.position;
        err = HAPIPByteBufferAppendStringWithFormat(
                &session->outboundBuffer,
                "HTTP/1.1 207 Multi-Status\r\n"
                "Content-Type: application/hap+json\r\n"
                "Content-Length: %lu\r\n\r\n",
                (unsigned long) content_length);
        HAPAssert(!err);
        if (content_length <= session->outboundBuffer.limit - session->outboundBuffer.position) {
            mark = session->outboundBuffer.position;
            err = HAPIPAccessoryProtocolGetCharacteristicWriteResponseBytes(
                    HAPNonnull(session->server), contexts, contexts_count, &session->outboundBuffer);
            HAPAssert(!err && (session->outboundBuffer.position - mark == content_length));
        } else {
            HAPLog(&logObject, "Out of resources (outbound buffer too small).");
            session->outboundBuffer.position = mark;
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
        }
    } else {
        HAPLog(&logObject, "Content length exceeding UINT32_MAX.");
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
    }
    HAP_DIAGNOSTIC_RESTORE_ICCARM(Pa084)
}

static void schedule_event_notifications(HAPAccessoryServerRef* server_);

static void handle_event_notification_timer(HAPPlatformTimerRef timer, void* _Nullable context) {
    HAPPrecondition(context);
    HAPAccessoryServerRef* server_ = context;
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;
    HAPPrecondition(timer == server->ip.eventNotificationTimer);
    server->ip.eventNotificationTimer = 0;

    HAPLogDebug(&logObject, "Event notification timer expired.");
    schedule_event_notifications(server_);
}

static void write_event_notifications(HAPIPSessionDescriptor* session);

static void schedule_event_notifications(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    if (server->ip.eventNotificationTimer) {
        HAPPlatformTimerDeregister(server->ip.eventNotificationTimer);
        server->ip.eventNotificationTimer = 0;
    }

    HAPError err;

    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
        HAPIPSession* ipSession = &server->ip.storage->sessions[i];
        HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) &ipSession->descriptor;
        if (!session->server) {
            continue;
        }

        if (session->state == kHAPIPSessionState_Reading &&
            session->inboundBuffer.position == 0 &&
            session->inProgress.state == kHAPIPSessionInProgressState_None &&
            session->numEventNotificationFlags > 0) {
            write_event_notifications(session);
        }
    }

    HAPTime clock_now_ms = HAPPlatformClockGetCurrent();
    int64_t timeout_ms = -1;

    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
        HAPIPSession* ipSession = &server->ip.storage->sessions[i];
        HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) &ipSession->descriptor;
        if (!session->server) {
            continue;
        }

        if (session->state == kHAPIPSessionState_Reading &&
            session->inboundBuffer.position == 0 &&
            session->inProgress.state == kHAPIPSessionInProgressState_None &&
            session->numEventNotificationFlags > 0) {
            HAPAssert(clock_now_ms >= session->eventNotificationStamp);
            HAPTime dt_ms = clock_now_ms - session->eventNotificationStamp;
            HAP_DIAGNOSTIC_PUSH
            HAP_DIAGNOSTIC_IGNORED_ARMCC(186)
            HAP_DIAGNOSTIC_IGNORED_GCC("-Wtype-limits")
            if (dt_ms < kHAPIPAccessoryServer_MaxEventNotificationDelay) {
                HAPAssert(kHAPIPAccessoryServer_MaxEventNotificationDelay <= INT64_MAX);
                int64_t t_ms = (int64_t)(kHAPIPAccessoryServer_MaxEventNotificationDelay - dt_ms);
                if ((timeout_ms == -1) || (t_ms < timeout_ms)) {
                    timeout_ms = t_ms;
                }
            } else {
                timeout_ms = 0;
            }
            HAP_DIAGNOSTIC_POP
        }
    }

    if (timeout_ms >= 0) {
        HAPTime deadline_ms;

        if (UINT64_MAX - clock_now_ms < (HAPTime) timeout_ms) {
            HAPLog(&logObject, "Clipping event notification timer to avoid clock overflow.");
            deadline_ms = UINT64_MAX;
        } else {
            deadline_ms = clock_now_ms + (HAPTime) timeout_ms;
        }
        HAPAssert(deadline_ms >= clock_now_ms);

        err = HAPPlatformTimerRegister(
                &server->ip.eventNotificationTimer, deadline_ms, handle_event_notification_timer, server_);
        if (err) {
            HAPLog(&logObject, "Not enough resources to schedule event notification timer!");
            HAPFatalError();
        }
        HAPAssert(server->ip.eventNotificationTimer);
    }
}

static HAPIPSessionDescriptor* get_session_desc_by_session_ref(HAPAccessoryServer* server, HAPSessionRef* session)
{
    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
        HAPIPSession* ipSession = &server->ip.storage->sessions[i];
        HAPIPSessionDescriptor* desc = (HAPIPSessionDescriptor*)&ipSession->descriptor;
        if (&desc->securitySession.session == session) {
            return desc;
        }
    }
    return NULL;
}

static void output(HAPIPSessionDescriptor* session) {
    HAPAssert(session->outboundBuffer.data);
    HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
    HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);

    size_t encrypted_length;

    HAPIPByteBufferFlip(&session->outboundBuffer);
    HAPLogBufferDebug(
            &logObject,
            session->outboundBuffer.data,
            session->outboundBuffer.limit,
            "session:%p:<",
            (const void*) session);

    if (session->securitySession.isSecured) {
        encrypted_length = HAPIPSecurityProtocolGetNumEncryptedBytes(
                session->outboundBuffer.limit - session->outboundBuffer.position);
        if (encrypted_length > session->outboundBuffer.capacity - session->outboundBuffer.position) {
            HAPLog(&logObject, "Out of resources (outbound buffer too small).");
            session->outboundBuffer.limit = session->outboundBuffer.capacity;
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
            HAPIPByteBufferFlip(&session->outboundBuffer);
            encrypted_length = HAPIPSecurityProtocolGetNumEncryptedBytes(
                    session->outboundBuffer.limit - session->outboundBuffer.position);
            HAPAssert(encrypted_length <= session->outboundBuffer.capacity - session->outboundBuffer.position);
        }
        HAPIPSecurityProtocolEncryptData(
                HAPNonnull(session->server), &session->securitySession.session, &session->outboundBuffer);
        HAPAssert(encrypted_length == session->outboundBuffer.limit - session->outboundBuffer.position);
    }
    session->state = kHAPIPSessionState_Writing;
}

/**
 * Handles a set of characteristic write requests.
 *
 * @param      session              IP session descriptor.
 * @param      contexts             Request contexts.
 * @param      numContexts          Length of @p contexts.
 * @param      dataBuffer           Buffer for values of type data, string or TLV8.
 * @param      timedWrite           Whether the request was a valid Execute Write Request or a regular Write Request.
 * @returns the number of in progress write requests.
 */
static size_t handle_characteristic_write_requests(
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContextRef* contexts,
        size_t numContexts,
        HAPIPByteBuffer* dataBuffer,
        bool* mutliStatus,
        bool timedWrite) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(contexts);
    HAPPrecondition(dataBuffer);
    HAPPrecondition(mutliStatus);
    HAPPrecondition(*mutliStatus == false);

    size_t numInProgress = 0;

    for (size_t i = 0; i < numContexts; i++) {
        HAPIPCharacteristicContext* context = (HAPIPCharacteristicContext*) &contexts[i];
        const HAPCharacteristic* characteristic;
        const HAPService* service;
        const HAPAccessory* accessory;
        get_db_ctx(session->server, context->aid, context->iid, &characteristic, &service, &accessory);
        if (characteristic) {
            HAPAssert(service);
            HAPAssert(accessory);
            server->ip.characteristicWriteRequestContext.ipSession = NULL;
            for (size_t j = 0; j < server->ip.storage->numSessions; j++) {
                HAPIPSession* ipSession = &server->ip.storage->sessions[j];
                HAPIPSessionDescriptor* t = (HAPIPSessionDescriptor*) &ipSession->descriptor;
                if (t->server && (t == session)) {
                    HAPAssert(!server->ip.characteristicWriteRequestContext.ipSession);
                    server->ip.characteristicWriteRequestContext.ipSession = ipSession;
                }
            }
            HAPAssert(server->ip.characteristicWriteRequestContext.ipSession);
            server->ip.characteristicWriteRequestContext.characteristic = characteristic;
            server->ip.characteristicWriteRequestContext.service = service;
            server->ip.characteristicWriteRequestContext.accessory = accessory;
            const HAPBaseCharacteristic* baseCharacteristic = characteristic;
            if ((context->write.type != kHAPIPWriteValueType_None) &&
                baseCharacteristic->properties.requiresTimedWrite && !timedWrite) {
                // If the accessory receives a standard write request on a characteristic which requires timed write,
                // the accessory must respond with HAP status error code -70410 (HAPIPStatusErrorCodeInvalidWrite).
                // See HomeKit Accessory Protocol Specification R14
                // Section 6.7.2.4 Timed Write Procedures
                HAPLogCharacteristic(
                        &logObject,
                        characteristic,
                        service,
                        accessory,
                        "Rejected write: Only timed writes are supported.");
                context->status = kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
            } else {
                HAPIPCharacteristicHandleWriteRequest(
                        (HAPIPSessionDescriptorRef*) session,
                        characteristic,
                        service,
                        accessory,
                        &contexts[i],
                        dataBuffer);
            }
            server->ip.characteristicWriteRequestContext.ipSession = NULL;
            server->ip.characteristicWriteRequestContext.characteristic = NULL;
            server->ip.characteristicWriteRequestContext.service = NULL;
            server->ip.characteristicWriteRequestContext.accessory = NULL;
        } else {
            context->status = kHAPIPAccessoryServerStatusCode_ResourceDoesNotExist;
        }
        if (context->status == kHAPIPAccessoryServerStatusCode_InPorgress) {
            numInProgress++;
        } else if (*mutliStatus == false && (context->status != kHAPIPAccessoryServerStatusCode_Success ||
            context->write.response)) {
            *mutliStatus = true;
        }
    }
    return numInProgress;
}

static void put_characteristics(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(session->inProgress.state == kHAPIPSessionInProgressState_None);
    HAPPrecondition(session->inProgress.numContexts == 0);
    HAPPrecondition(session->inProgress.mutliStatus == false);

    HAPError err;
    size_t i;
    bool pid_valid;
    bool mutliStatus = false;
    uint64_t pid;

    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->httpReaderPosition <= session->inboundBuffer.position);
    if (session->httpContentLength.isDefined) {
        HAPAssert(session->httpContentLength.value <= session->inboundBuffer.position - session->httpReaderPosition);
        err = HAPIPAccessoryProtocolGetCharacteristicWriteRequests(
                &session->inboundBuffer.data[session->httpReaderPosition],
                session->httpContentLength.value,
                session->contexts,
                session->maxContexts,
                &session->numContexts,
                &pid_valid,
                &pid);
        if (!err) {
            if ((session->timedWriteExpirationTime && pid_valid &&
                 session->timedWriteExpirationTime < HAPPlatformClockGetCurrent()) ||
                (session->timedWriteExpirationTime && pid_valid && session->timedWritePID != pid) ||
                (!session->timedWriteExpirationTime && pid_valid)) {
                // If the accessory receives an Execute Write Request after the TTL has expired it must ignore the
                // request and respond with HAP status error code -70410 (HAPIPStatusErrorCodeInvalidWrite).
                // See HomeKit Accessory Protocol Specification R14
                // Section 6.7.2.4 Timed Write Procedures
                HAPLog(&logObject, "Rejecting expired Execute Write Request.");
                for (i = 0; i < session->numContexts; i++) {
                    ((HAPIPCharacteristicContext*) &session->contexts[i])->status =
                            kHAPIPAccessoryServerStatusCode_InvalidValueInWrite;
                }
                HAPAssert(i == session->numContexts);
                write_characteristic_write_response(session, session->contexts, session->numContexts);
            } else if (session->numContexts == 0) {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_NoContent);
            } else {
                HAPIPByteBufferClear(&session->scratchBuffer);
                session->inProgress.numContexts = handle_characteristic_write_requests(
                        session,
                        session->contexts,
                        session->numContexts,
                        &session->scratchBuffer,
                        &mutliStatus,
                        pid_valid);
                if (session->inProgress.numContexts) {
                    session->inProgress.state = kHAPIPSessionInProgressState_PutCharacteristics;
                    session->inProgress.mutliStatus = mutliStatus;
                    return;
                }
                if (mutliStatus) {
                    write_characteristic_write_response(session, session->contexts, session->numContexts);
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_NoContent);
                }
            }
            // Reset timed write transaction.
            if (session->timedWriteExpirationTime && pid_valid) {
                session->timedWriteExpirationTime = 0;
                session->timedWritePID = 0;
            }
        } else if (err == kHAPError_OutOfResources) {
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
        } else {
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
        }
    } else {
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
    }
}

HAP_RESULT_USE_CHECK
static size_t handle_characteristic_read_requests(
        HAPIPSessionDescriptor* session,
        HAPIPSessionContext session_context,
        HAPIPCharacteristicContextRef* contexts,
        size_t contexts_count,
        bool* mutliStatus,
        HAPIPByteBuffer* data_buffer) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(contexts);
    HAPPrecondition(mutliStatus);
    HAPPrecondition(*mutliStatus == false);

    size_t numInProgress = 0;
    size_t i, j;
    const HAPCharacteristic* c;
    const HAPService* svc;
    const HAPAccessory* acc;

    for (i = 0; i < contexts_count; i++) {
        HAPIPCharacteristicContext* context = (HAPIPCharacteristicContext*) &contexts[i];

        get_db_ctx(session->server, context->aid, context->iid, &c, &svc, &acc);
        if (c) {
            const HAPBaseCharacteristic* chr = c;
            HAPAssert(chr->iid == context->iid);
            HAPAssert(session->numEventNotifications <= session->maxEventNotifications);
            j = 0;
            while ((j < session->numEventNotifications) &&
                   ((((HAPIPEventNotification*) &session->eventNotifications[j])->aid != context->aid) ||
                    (((HAPIPEventNotification*) &session->eventNotifications[j])->iid != context->iid))) {
                j++;
            }
            HAPAssert(
                    (j == session->numEventNotifications) ||
                    ((j < session->numEventNotifications) &&
                     (((HAPIPEventNotification*) &session->eventNotifications[j])->aid == context->aid) &&
                     (((HAPIPEventNotification*) &session->eventNotifications[j])->iid == context->iid)));
            context->read.ev = j < session->numEventNotifications;
            if (!HAPCharacteristicReadRequiresAdminPermissions(chr) ||
                HAPSessionControllerIsAdmin(&session->securitySession.session)) {
                if (chr->properties.readable) {
                    if ((session_context != kHAPIPSessionContext_EventNotification) &&
                        HAPUUIDAreEqual(chr->characteristicType, &kHAPCharacteristicType_ProgrammableSwitchEvent)) {
                        // A read of this characteristic must always return a null value for IP accessories.
                        // See HomeKit Accessory Protocol Specification R14
                        // Section 9.75 Programmable Switch Event
                        context->status = kHAPIPAccessoryServerStatusCode_Success;
                        context->value.unsignedIntValue = 0;
                    } else if (
                            (session_context == kHAPIPSessionContext_GetAccessories) &&
                            chr->properties.ip.controlPoint) {
                        context->status = kHAPIPAccessoryServerStatusCode_UnableToPerformOperation;
                    } else {
                        HAPIPCharacteristicHandleReadRequest(
                                (HAPIPSessionDescriptorRef*) session,
                                chr,
                                svc,
                                acc,
                                (HAPIPCharacteristicContextRef*) context,
                                data_buffer);
                    }
                } else {
                    context->status = kHAPIPAccessoryServerStatusCode_ReadFromWriteOnlyCharacteristic;
                }
            } else {
                context->status = kHAPIPAccessoryServerStatusCode_InsufficientPrivileges;
            }
        } else {
            context->status = kHAPIPAccessoryServerStatusCode_ResourceDoesNotExist;
        }
        if (context->status == kHAPIPAccessoryServerStatusCode_InPorgress) {
            numInProgress++;
        } else if (context->status != kHAPIPAccessoryServerStatusCode_Success) {
            *mutliStatus = true;
        }
    }
    HAPAssert(i == contexts_count);
    return numInProgress;
}

static void write_characteristic_read_response(
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContextRef* contexts,
        size_t contexts_count,
        HAPIPReadRequestParameters* parameters,
        bool mutliStatus) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));

    HAPError err;
    size_t content_length, mark;

    content_length = HAPIPAccessoryProtocolGetNumCharacteristicReadResponseBytes(
            session->server,
            contexts,
            contexts_count,
            parameters);
    HAPAssert(session->outboundBuffer.data);
    HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
    HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);
    mark = session->outboundBuffer.position;
    if (!mutliStatus) {
        err = HAPIPByteBufferAppendStringWithFormat(&session->outboundBuffer, "HTTP/1.1 200 OK\r\n");
    } else {
        err = HAPIPByteBufferAppendStringWithFormat(
                &session->outboundBuffer, "HTTP/1.1 207 Multi-Status\r\n");
    }
    HAPAssert(!err);
    HAP_DIAGNOSTIC_IGNORED_ICCARM(Pa084)
    if (content_length <= UINT32_MAX) {
        err = HAPIPByteBufferAppendStringWithFormat(
                &session->outboundBuffer,
                "Content-Type: application/hap+json\r\n"
                "Content-Length: %lu\r\n\r\n",
                (unsigned long) content_length);
        HAPAssert(!err);
        if (content_length <= session->outboundBuffer.limit - session->outboundBuffer.position) {
            mark = session->outboundBuffer.position;
            err = HAPIPAccessoryProtocolGetCharacteristicReadResponseBytes(
                    HAPNonnull(session->server),
                    contexts,
                    contexts_count,
                    parameters,
                    &session->outboundBuffer);
            HAPAssert(!err && (session->outboundBuffer.position - mark == content_length));
        } else {
            HAPLog(&logObject, "Out of resources (outbound buffer too small).");
            session->outboundBuffer.position = mark;
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
        }
    } else {
        HAPLog(&logObject, "Content length exceeding UINT32_MAX.");
        session->outboundBuffer.position = mark;
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
    }
    HAP_DIAGNOSTIC_RESTORE_ICCARM(Pa084)
}

static void get_characteristics(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(session->inProgress.state == kHAPIPSessionInProgressState_None);
    HAPPrecondition(session->inProgress.numContexts == 0);
    HAPPrecondition(session->inProgress.mutliStatus == false);

    HAPError err;
    bool mutliStatus = false;
    HAPIPReadRequestParameters parameters;

    HAPAssert(
            (session->httpURI.numBytes >= 16) &&
            HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/characteristics", 16));
    if ((session->httpURI.numBytes >= 17) && (session->httpURI.bytes[16] == '?')) {
        err = HAPIPAccessoryProtocolGetCharacteristicReadRequests(
                &session->httpURI.bytes[17],
                session->httpURI.numBytes - 17,
                session->contexts,
                session->maxContexts,
                &session->numContexts,
                &parameters);
        if (!err) {
            if (session->numContexts == 0) {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_NoContent);
            } else {
                HAPIPByteBufferClear(&session->scratchBuffer);
                session->inProgress.numContexts = handle_characteristic_read_requests(
                        session,
                        kHAPIPSessionContext_GetCharacteristics,
                        session->contexts,
                        session->numContexts,
                        &mutliStatus,
                        &session->scratchBuffer);
                if (session->inProgress.numContexts) {
                    session->inProgress.state = kHAPIPSessionInProgressState_GetCharacteristics;
                    session->inProgress.mutliStatus = mutliStatus;
                    session->inProgress.parameters = parameters;
                    return;
                }
                write_characteristic_read_response(
                        session,
                        session->contexts,
                        session->numContexts,
                        &parameters,
                        mutliStatus);
            }
        } else if (err == kHAPError_OutOfResources) {
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
        } else {
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
        }
    } else {
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
    }
}

static void handle_accessory_serialization(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));

    HAPError err;

    HAPAssert(session->outboundBuffer.data);
    HAPAssert(session->outboundBuffer.capacity);
    if (session->inProgress.state == kHAPIPSessionInProgressState_GetAccessories) {
        HAPAssert(session->outboundBuffer.position == session->outboundBuffer.limit);
        if (session->inProgress.numContexts) {
            session->state = kHAPIPSessionState_Reading;
            return;
        }
        if (session->securitySession.isSecured) {
            HAPAssert(session->outboundBuffer.limit <= session->outboundBufferMark);
            HAPAssert(session->outboundBufferMark <= session->outboundBuffer.capacity);
            HAPRawBufferCopyBytes(
                    &session->outboundBuffer.data[0],
                    &session->outboundBuffer.data[session->outboundBuffer.limit],
                    session->outboundBufferMark - session->outboundBuffer.limit);
            session->outboundBuffer.position = session->outboundBufferMark - session->outboundBuffer.limit;
            session->outboundBuffer.limit = session->outboundBuffer.capacity;
            session->outboundBufferMark = 0;
        } else {
            HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);
            session->outboundBuffer.position = 0;
            session->outboundBuffer.limit = session->outboundBuffer.capacity;
        }
    } else {
        HAPAssert(session->inProgress.numContexts == 0);
    }

    HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
    HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);

    if ((session->outboundBuffer.position < session->outboundBuffer.limit) &&
        (session->outboundBuffer.position < kHAPIPSecurityProtocol_MaxFrameBytes) &&
        !HAPIPAccessorySerializationIsComplete(&session->accessorySerializationContext)) {
        size_t numBytesSerialized;
        size_t maxBytes = session->outboundBuffer.limit - session->outboundBuffer.position;
        size_t minBytes =
                kHAPIPSecurityProtocol_MaxFrameBytes < maxBytes ? kHAPIPSecurityProtocol_MaxFrameBytes : maxBytes;
        err = HAPIPAccessorySerializeReadResponse(
                &session->accessorySerializationContext,
                HAPNonnull(session->server),
                (HAPIPSessionDescriptorRef*) session,
                &session->outboundBuffer.data[session->outboundBuffer.position],
                minBytes,
                maxBytes,
                &numBytesSerialized,
                &session->contexts[0],
                &session->scratchBuffer);
        if (err == kHAPError_InProgress) {
            session->inProgress.numContexts = 1;
            session->numContexts = 1;
        } else if (err) {
            HAPAssert(err == kHAPError_OutOfResources);
            HAPLogError(&logObject, "Invalid configuration (outbound buffer too small).");
            HAPFatalError();
        }
        HAPAssert(numBytesSerialized > 0);
        HAPAssert(numBytesSerialized <= maxBytes);
        HAPAssert(
                numBytesSerialized >= minBytes ||
                err == kHAPError_InProgress ||
                HAPIPAccessorySerializationIsComplete(&session->accessorySerializationContext));

        // maxProtocolBytes = max(8, size_t represented in HEX + '\r' + '\n' + '\0')
        char protocolBytes[HAPMax(8, sizeof(size_t) * 2 + 2 + 1)];

        err = HAPStringWithFormat(protocolBytes, sizeof protocolBytes, "%zX\r\n", numBytesSerialized);
        HAPAssert(!err);
        size_t numProtocolBytes = HAPStringGetNumBytes(protocolBytes);

        if (numProtocolBytes > session->outboundBuffer.limit - session->outboundBuffer.position) {
            HAPLogError(&logObject, "Invalid configuration (outbound buffer too small).");
            HAPFatalError();
        }
        if (numBytesSerialized > session->outboundBuffer.limit - session->outboundBuffer.position - numProtocolBytes) {
            HAPLogError(&logObject, "Invalid configuration (outbound buffer too small).");
            HAPFatalError();
        }

        HAPRawBufferCopyBytes(
                &session->outboundBuffer.data[session->outboundBuffer.position + numProtocolBytes],
                &session->outboundBuffer.data[session->outboundBuffer.position],
                numBytesSerialized);
        HAPRawBufferCopyBytes(
                &session->outboundBuffer.data[session->outboundBuffer.position], protocolBytes, numProtocolBytes);
        session->outboundBuffer.position += numProtocolBytes + numBytesSerialized;

        if (HAPIPAccessorySerializationIsComplete(&session->accessorySerializationContext)) {
            err = HAPStringWithFormat(protocolBytes, sizeof protocolBytes, "\r\n0\r\n\r\n");
        } else {
            err = HAPStringWithFormat(protocolBytes, sizeof protocolBytes, "\r\n");
        }
        HAPAssert(!err);
        numProtocolBytes = HAPStringGetNumBytes(protocolBytes);

        if (numProtocolBytes > session->outboundBuffer.limit - session->outboundBuffer.position) {
            HAPLogError(&logObject, "Invalid configuration (outbound buffer too small).");
            HAPFatalError();
        }

        HAPRawBufferCopyBytes(
                &session->outboundBuffer.data[session->outboundBuffer.position], protocolBytes, numProtocolBytes);
        session->outboundBuffer.position += numProtocolBytes;
    }

    if (session->outboundBuffer.position > 0) {
        HAPIPByteBufferFlip(&session->outboundBuffer);

        if (session->securitySession.isSecured) {
            size_t numFrameBytes = kHAPIPSecurityProtocol_MaxFrameBytes <
                                                   session->outboundBuffer.limit - session->outboundBuffer.position ?
                                           kHAPIPSecurityProtocol_MaxFrameBytes :
                                           session->outboundBuffer.limit - session->outboundBuffer.position;

            HAPLogBufferDebug(
                    &logObject,
                    &session->outboundBuffer.data[session->outboundBuffer.position],
                    numFrameBytes,
                    "session:%p:<",
                    (const void*) session);

            size_t numUnencryptedBytes =
                    session->outboundBuffer.limit - session->outboundBuffer.position - numFrameBytes;

            size_t numEncryptedBytes = HAPIPSecurityProtocolGetNumEncryptedBytes(numFrameBytes);
            if (numEncryptedBytes >
                session->outboundBuffer.capacity - session->outboundBuffer.position - numUnencryptedBytes) {
                HAPLogError(&logObject, "Invalid configuration (outbound buffer too small).");
                HAPFatalError();
            }

            HAPRawBufferCopyBytes(
                    &session->outboundBuffer.data[session->outboundBuffer.position + numEncryptedBytes],
                    &session->outboundBuffer.data[session->outboundBuffer.position + numFrameBytes],
                    numUnencryptedBytes);

            session->outboundBuffer.limit = session->outboundBuffer.position + numFrameBytes;

            HAPIPSecurityProtocolEncryptData(
                    HAPNonnull(session->server), &session->securitySession.session, &session->outboundBuffer);
            HAPAssert(numEncryptedBytes == session->outboundBuffer.limit - session->outboundBuffer.position);

            session->outboundBufferMark = session->outboundBuffer.limit + numUnencryptedBytes;
        } else {
            HAPLogBufferDebug(
                    &logObject,
                    &session->outboundBuffer.data[session->outboundBuffer.position],
                    session->outboundBuffer.limit - session->outboundBuffer.position,
                    "session:%p:<",
                    (const void*) session);
        }

        session->state = kHAPIPSessionState_Writing;

        session->inProgress.state = kHAPIPSessionInProgressState_GetAccessories;
    } else {
        session->inProgress.state = kHAPIPSessionInProgressState_None;

        session->state = kHAPIPSessionState_Reading;
        prepare_reading_request(session);
        if (session->inboundBuffer.position != 0) {
            handle_input(session);
        }
    }
}

static void get_accessories(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(session->inProgress.state == kHAPIPSessionInProgressState_None);

    HAPError err;

    HAPAssert(session->outboundBuffer.data);
    HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
    HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);
    err = HAPIPByteBufferAppendStringWithFormat(
            &session->outboundBuffer,
            "HTTP/1.1 200 OK\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Type: application/hap+json\r\n\r\n");
    HAPAssert(!err);

    HAPIPAccessoryCreateSerializationContext(&session->accessorySerializationContext);
    handle_accessory_serialization(session);
}

static void handle_pairing_data(
        HAPIPSessionDescriptor* session,
        HAPError (*write_hap_pairing_data)(
                HAPAccessoryServerRef* p_acc,
                HAPSessionRef* p_sess,
                HAPTLVReaderRef* p_reader),
        HAPError (*read_hap_pairing_data)(
                HAPAccessoryServerRef* p_acc,
                HAPSessionRef* p_sess,
                HAPTLVWriterRef* p_writer)) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(session->securitySession.isOpen);

    HAPError err;

    int r;
    bool pairing_status;
    uint8_t* p_tlv8_buffer;
    size_t tlv8_length, mark;
    HAPTLVReaderOptions tlv8_reader_init;
    HAPTLVReaderRef tlv8_reader;
    HAPTLVWriterRef tlv8_writer;

    char* scratchBuffer = session->scratchBuffer.data;
    size_t maxScratchBufferBytes = session->scratchBuffer.capacity;

    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->httpReaderPosition <= session->inboundBuffer.position);
    HAPAssert(write_hap_pairing_data);
    HAPAssert(read_hap_pairing_data);
    pairing_status = HAPAccessoryServerIsPaired(HAPNonnull(session->server));
    if (session->httpContentLength.isDefined) {
        HAPAssert(session->httpContentLength.value <= session->inboundBuffer.position - session->httpReaderPosition);
        if (session->httpContentLength.value <= maxScratchBufferBytes) {
            HAPRawBufferCopyBytes(
                    scratchBuffer,
                    &session->inboundBuffer.data[session->httpReaderPosition],
                    session->httpContentLength.value);
            tlv8_reader_init.bytes = scratchBuffer;
            tlv8_reader_init.numBytes = session->httpContentLength.value;
            tlv8_reader_init.maxBytes = maxScratchBufferBytes;
            HAPTLVReaderCreateWithOptions(&tlv8_reader, &tlv8_reader_init);
            r = write_hap_pairing_data(HAPNonnull(session->server), &session->securitySession.session, &tlv8_reader);
            if (r == 0) {
                HAPTLVWriterCreate(&tlv8_writer, scratchBuffer, maxScratchBufferBytes);
                r = read_hap_pairing_data(HAPNonnull(session->server), &session->securitySession.session, &tlv8_writer);
                if (r == 0) {
                    HAPTLVWriterGetBuffer(&tlv8_writer, (void*) &p_tlv8_buffer, &tlv8_length);
                    if (HAPAccessoryServerIsPaired(HAPNonnull(session->server)) != pairing_status) {
                        HAPIPServiceDiscoverySetHAPService(HAPNonnull(session->server));
                    }
                    HAPAssert(session->outboundBuffer.data);
                    HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
                    HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);
                    mark = session->outboundBuffer.position;
                    HAP_DIAGNOSTIC_IGNORED_ICCARM(Pa084)
                    if (tlv8_length <= UINT32_MAX) {
                        err = HAPIPByteBufferAppendStringWithFormat(
                                &session->outboundBuffer,
                                "HTTP/1.1 200 OK\r\n"
                                "Content-Type: application/pairing+tlv8\r\n"
                                "Content-Length: %lu\r\n\r\n",
                                (unsigned long) tlv8_length);
                        HAPAssert(!err);
                        if (tlv8_length <= session->outboundBuffer.limit - session->outboundBuffer.position) {
                            HAPRawBufferCopyBytes(
                                    &session->outboundBuffer.data[session->outboundBuffer.position],
                                    p_tlv8_buffer,
                                    tlv8_length);
                            session->outboundBuffer.position += tlv8_length;
                            for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
                                HAPIPSession* ipSession = &server->ip.storage->sessions[i];
                                HAPIPSessionDescriptor* t = (HAPIPSessionDescriptor*) &ipSession->descriptor;
                                if (!t->server) {
                                    continue;
                                }

                                // Other sessions whose pairing has been removed during the pairing session
                                // need to be closed as soon as possible.
                                if (t != session && t->state == kHAPIPSessionState_Reading &&
                                    t->securitySession.isSecured && !HAPSessionIsSecured(&t->securitySession.session)) {
                                    HAPLogInfo(&logObject, "Closing other session whose pairing has been removed.");
                                    CloseSession(t);
                                }
                            }
                        } else {
                            HAPLog(&logObject, "Invalid configuration (outbound buffer too small).");
                            session->outboundBuffer.position = mark;
                            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_InternalServerError);
                        }
                        HAP_DIAGNOSTIC_RESTORE_ICCARM(Pa084)
                    } else {
                        HAPLog(&logObject, "Content length exceeding UINT32_MAX.");
                        session->outboundBuffer.position = mark;
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
                    }
                } else {
                    log_result(
                            kHAPLogType_Error,
                            "error:Function 'read_hap_pairing_data' failed.",
                            r,
                            __func__,
                            HAP_FILE,
                            __LINE__);
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_InternalServerError);
                }
            } else {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
            }
        } else {
            HAPLog(&logObject, "Invalid configuration (inbound buffer too small).");
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_InternalServerError);
        }
    } else {
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
    }
}

/**
 * Handles a POST request on the /secure-message endpoint.
 *
 * - Session has already been validated to be secured.
 *
 * @param      session              IP session descriptor.
 */
static void handle_secure_message(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(server->primaryAccessory);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(session->inboundBuffer.data);
    HAPPrecondition(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPPrecondition(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPPrecondition(session->httpReaderPosition <= session->inboundBuffer.position);

    HAPError err;

    // Validate request.
    // Requests use the HAP PDU format.
    // See HomeKit Accessory Protocol Specification R14
    // Section 7.3.3 HAP PDU Format
    if (session->httpContentType != kHAPIPAccessoryServerContentType_Application_OctetStream) {
        HAPLog(&logObject, "Received unexpected Content-Type in /secure-message request.");
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
        return;
    }
    if (!session->httpContentLength.isDefined) {
        HAPLog(&logObject, "Received malformed /secure-message request (no content length).");
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
        return;
    }
    HAPAssert(session->httpContentLength.value <= session->inboundBuffer.position - session->httpReaderPosition);
    uint8_t* requestBytes = (uint8_t*) &session->inboundBuffer.data[session->httpReaderPosition];
    size_t numRequestBytes = session->httpContentLength.value;
    if (numRequestBytes < 5) {
        HAPLog(&logObject, "Received too short /secure-message request.");
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
        return;
    }
    if (requestBytes[0] != ((0 << 7) | (0 << 4) | (0 << 3) | (0 << 2) | (0 << 1) | (0 << 0))) {
        HAPLog(&logObject, "Received malformed /secure-message request (control field: 0x%02x).", requestBytes[0]);
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
        return;
    }
    uint8_t opcode = requestBytes[1];
    uint8_t tid = (uint8_t) requestBytes[2];
    uint16_t iid = HAPReadLittleUInt16(&requestBytes[3]);
    HAPTLVReaderRef requestBodyReader;
    if (numRequestBytes <= 5) {
        HAPAssert(numRequestBytes == 5);
        HAPTLVReaderCreate(&requestBodyReader, NULL, 0);
    } else {
        if (numRequestBytes < 7) {
            HAPLog(&logObject, "Received malformed /secure-message request (malformed body length).");
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
            return;
        }
        uint16_t numRequestBodyBytes = HAPReadLittleUInt16(&requestBytes[5]);
        if (numRequestBytes - 7 != numRequestBodyBytes) {
            HAPLog(&logObject, "Received malformed /secure-message request (incorrect body length).");
            write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
            return;
        }
        HAPTLVReaderCreate(&requestBodyReader, &requestBytes[7], numRequestBodyBytes);
    }

    // Response variables.
    HAPBLEPDUStatus status;
    void* _Nullable responseBodyBytes = NULL;
    size_t numResponseBodyBytes = 0;

    // Validate opcode.
    if (!HAPPDUIsValidOpcode(opcode)) {
        // If an accessory receives a HAP PDU with an opcode that it does not support it shall reject the PDU and
        // respond with a status code Unsupported PDU in its HAP response.
        // See HomeKit Accessory Protocol Specification R14
        // Section 7.3.3.2 HAP Request Format
        HAPLogAccessory(
                &logObject,
                server->primaryAccessory,
                "Rejected /secure-message request with unsupported opcode: 0x%02x.",
                opcode);
        status = kHAPBLEPDUStatus_UnsupportedPDU;
        goto SendResponse;
    }

    // Validate iid.
    // For IP accessories instance ID in the request shall be set to 0.
    // See HomeKit Accessory Protocol Specification R14
    // Section 5.15 Software Authentication Procedure
    if (iid) {
        HAPLogAccessory(
                &logObject,
                server->primaryAccessory,
                "Request's IID [00000000%08X] does not match the addressed IID.",
                iid);
        status = kHAPBLEPDUStatus_InvalidInstanceID;
        goto SendResponse;
    }

#define DestroyRequestBodyAndCreateResponseBodyWriter(responseWriter) \
    do { \
        size_t numBytes = session->scratchBuffer.capacity; \
        if (numBytes > UINT16_MAX) { \
            /* Maximum for HAP-BLE PDU. */ \
            numBytes = UINT16_MAX; \
        } \
        HAPTLVWriterCreate(responseWriter, session->scratchBuffer.data, numBytes); \
    } while (0)

    // Handle request.
    HAPAssert(sizeof opcode == sizeof(HAPPDUOpcode));
    switch ((HAPPDUOpcode) opcode) {
        case kHAPPDUOpcode_ServiceSignatureRead:
        case kHAPPDUOpcode_CharacteristicSignatureRead:
        case kHAPPDUOpcode_CharacteristicConfiguration:
        case kHAPPDUOpcode_ProtocolConfiguration:
        case kHAPPDUOpcode_CharacteristicTimedWrite:
        case kHAPPDUOpcode_CharacteristicExecuteWrite:
        case kHAPPDUOpcode_CharacteristicWrite:
        case kHAPPDUOpcode_CharacteristicRead: {
            HAPLogAccessory(
                    &logObject,
                    server->primaryAccessory,
                    "Rejected /secure-message request with opcode that is not supported by IP: 0x%02x.",
                    opcode);
            status = kHAPBLEPDUStatus_UnsupportedPDU;
        }
            goto SendResponse;
        case kHAPPDUOpcode_Token: {
            // See HomeKit Accessory Protocol Specification R14
            // Section 5.15.1 HAP-Token-Request
            HAPAssert(!iid);
            HAPAssert(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);

            // HAP-Token-Request ok.
            HAPTLVWriterRef writer;
            DestroyRequestBodyAndCreateResponseBodyWriter(&writer);

            // Serialize HAP-Token-Response.
            err = HAPMFiTokenAuthGetTokenResponse(
                    HAPNonnull(session->server),
                    &session->securitySession.session,
                    HAPNonnull(server->primaryAccessory),
                    &writer);
            if (err) {
                HAPAssert(err == kHAPError_Unknown || err == kHAPError_InvalidState || err == kHAPError_OutOfResources);
                HAPLogAccessory(
                        &logObject,
                        server->primaryAccessory,
                        "Rejected token request: Request handling failed with error %u.",
                        err);
                status = kHAPBLEPDUStatus_InvalidRequest;
                goto SendResponse;
            }
            HAPTLVWriterGetBuffer(&writer, &responseBodyBytes, &numResponseBodyBytes);
            status = kHAPBLEPDUStatus_Success;
        }
            goto SendResponse;
        case kHAPPDUOpcode_TokenUpdate: {
            // See HomeKit Accessory Protocol Specification R14
            // Section 5.15.3 HAP-Token-Update-Request
            HAPAssert(!iid);
            HAPAssert(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);

            // Handle HAP-Token-Update-Request.
            err = HAPMFiTokenAuthHandleTokenUpdateRequest(
                    HAPNonnull(session->server),
                    &session->securitySession.session,
                    HAPNonnull(server->primaryAccessory),
                    &requestBodyReader);
            if (err) {
                HAPAssert(err == kHAPError_Unknown || err == kHAPError_InvalidData);
                HAPLogAccessory(
                        &logObject,
                        server->primaryAccessory,
                        "Rejected token update request: Request handling failed with error %u.",
                        err);
                status = kHAPBLEPDUStatus_InvalidRequest;
                goto SendResponse;
            }

            // Send HAP-Token-Update-Response.
            status = kHAPBLEPDUStatus_Success;
        }
            goto SendResponse;
        case kHAPPDUOpcode_Info: {
            // See HomeKit Accessory Protocol Specification R14
            // Section 5.15.5 HAP-Info-Request
            HAPAssert(!iid);
            HAPAssert(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);

            // HAP-Info-Request ok.
            HAPTLVWriterRef writer;
            DestroyRequestBodyAndCreateResponseBodyWriter(&writer);

            // Serialize HAP-Info-Response.
            err = HAPAccessoryGetInfoResponse(
                    HAPNonnull(session->server),
                    &session->securitySession.session,
                    HAPNonnull(server->primaryAccessory),
                    &writer);
            if (err) {
                HAPAssert(err == kHAPError_Unknown || err == kHAPError_OutOfResources);
                HAPLogAccessory(
                        &logObject,
                        server->primaryAccessory,
                        "Rejected info request: Request handling failed with error %u.",
                        err);
                status = kHAPBLEPDUStatus_InvalidRequest;
                goto SendResponse;
            }
            HAPTLVWriterGetBuffer(&writer, &responseBodyBytes, &numResponseBodyBytes);
            status = kHAPBLEPDUStatus_Success;
        }
            goto SendResponse;
    }

#undef DestroyRequestBodyAndCreateResponseBodyWriter

    HAPFatalError();
SendResponse : {
    // Serialize response.
    // Responses use the HAP PDU format.
    // See HomeKit Accessory Protocol Specification R14
    // Section 7.3.3 HAP PDU Format
    size_t mark = session->outboundBuffer.position;
    size_t numResponseBytes = 3;
    if (responseBodyBytes) {
        numResponseBytes += 2;
        numResponseBytes += numResponseBodyBytes;
    }
    HAP_DIAGNOSTIC_IGNORED_ICCARM(Pa084)
    if (numResponseBytes > UINT32_MAX) {
        HAPLog(&logObject, "/secure-message response: Content length exceeds UINT32_MAX.");
        session->outboundBuffer.position = mark;
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_OutOfResources);
        return;
    }
    HAP_DIAGNOSTIC_RESTORE_ICCARM(Pa084)
    const char* contentType = "application/octet-stream";
    err = HAPIPByteBufferAppendStringWithFormat(
            &session->outboundBuffer,
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %lu\r\n\r\n",
            contentType,
            (unsigned long) numResponseBytes);
    if (err) {
        HAPAssert(err == kHAPError_OutOfResources);
        session->outboundBuffer.position = mark;
        HAPLog(&logObject, "/secure-message response: Invalid configuration (outbound buffer too small for headers).");
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_InternalServerError);
        return;
    }
    if (numResponseBytes > session->outboundBuffer.limit - session->outboundBuffer.position) {
        HAPAssert(err == kHAPError_OutOfResources);
        session->outboundBuffer.position = mark;
        HAPLog(&logObject, "/secure-message response: Invalid configuration (outbound buffer too small for body).");
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_InternalServerError);
        return;
    }
    session->outboundBuffer.data[session->outboundBuffer.position++] =
            (0 << 7) | (0 << 4) | (0 << 3) | (0 << 2) | (1 << 1) | (0 << 0);
    session->outboundBuffer.data[session->outboundBuffer.position++] = (char) tid;
    session->outboundBuffer.data[session->outboundBuffer.position++] = (char) status;
    if (responseBodyBytes) {
        HAPWriteLittleUInt16(&session->outboundBuffer.data[session->outboundBuffer.position], numResponseBodyBytes);
        session->outboundBuffer.position += 2;

        HAPRawBufferCopyBytes(
                &session->outboundBuffer.data[session->outboundBuffer.position],
                HAPNonnullVoid(responseBodyBytes),
                numResponseBodyBytes);
        session->outboundBuffer.position += numResponseBodyBytes;
    }
    HAPAssert(session->outboundBuffer.limit >= session->outboundBuffer.position);
}
}

static void identify_primary_accessory(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(server->primaryAccessory);
    HAPPrecondition(server->primaryAccessory->aid == kHAPIPAccessoryProtocolAID_PrimaryAccessory);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(!session->securitySession.isSecured);

    HAPError err;

    const HAPService* service = NULL;
    for (size_t i = 0; server->primaryAccessory->services[i]; i++) {
        const HAPService* s = server->primaryAccessory->services[i];
        if ((s->iid == kHAPIPAccessoryProtocolIID_AccessoryInformation) &&
            HAPUUIDAreEqual(s->serviceType, &kHAPServiceType_AccessoryInformation)) {
            service = s;
            break;
        }
    }
    if (service) {
        const HAPBaseCharacteristic* characteristic = NULL;
        for (size_t i = 0; service->characteristics[i]; i++) {
            const HAPBaseCharacteristic* c = service->characteristics[i];
            if (HAPUUIDAreEqual(c->characteristicType, &kHAPCharacteristicType_Identify) &&
                (c->format == kHAPCharacteristicFormat_Bool) && c->properties.writable) {
                characteristic = c;
                break;
            }
        }
        if (characteristic) {
            err = HAPBoolCharacteristicHandleWrite(
                    HAPNonnull(session->server),
                    &(const HAPBoolCharacteristicWriteRequest) {
                            .transportType = kHAPTransportType_IP,
                            .session = &session->securitySession.session,
                            .characteristic = (const HAPBoolCharacteristic*) characteristic,
                            .service = service,
                            .accessory = HAPNonnull(server->primaryAccessory),
                            .remote = false,
                            .authorizationData = { .bytes = NULL, .numBytes = 0 } },
                    true,
                    HAPAccessoryServerGetClientContext(HAPNonnull(session->server)));
            if (err) {
                HAPAssert(
                        err == kHAPError_Unknown || err == kHAPError_InvalidState || err == kHAPError_InvalidData ||
                        err == kHAPError_OutOfResources || err == kHAPError_NotAuthorized || err == kHAPError_Busy);
                HAPLog(&logObject, "Identify failed: %u.", err);
            }
        }
    }

    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_NoContent);
}

static void handle_http_request(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(session->securitySession.isOpen);

    HAPAssert(session->httpReader.state == util_HTTP_READER_STATE_DONE);
    HAPAssert(!session->httpParserError);

    {

        if ((session->httpURI.numBytes == 9) &&
            HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/identify", 9)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                if (!HAPAccessoryServerIsPaired(HAPNonnull(session->server))) {
                    identify_primary_accessory(session);
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_InsufficientPrivileges);
                }
            } else {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
            }
        } else if (
                (session->httpURI.numBytes == 11) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/pair-setup", 11)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                if (!session->securitySession.isSecured) {
                    // Close existing transient session.
                    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
                        HAPIPSession* ipSession = &server->ip.storage->sessions[i];
                        HAPIPSessionDescriptor* t = (HAPIPSessionDescriptor*) &ipSession->descriptor;
                        if (!t->server) {
                            continue;
                        }
                        // TODO Make this finish writing ongoing responses. Similar to Remove Pairing.
                        if (t != session && HAPSessionIsTransient(&t->securitySession.session)) {
                            HAPLog(&logObject,
                                   "Closing transient session "
                                   "due to /pair-setup while transient session is active.");
                            CloseSession(t);
                        }
                    }

                    // Handle message.
                    handle_pairing_data(session, HAPSessionHandlePairSetupWrite, HAPSessionHandlePairSetupRead);
                } else {
                    HAPLog(&logObject, "Rejected POST /pair-setup: Only non-secure access is supported.");
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                }
            } else {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
            }
        } else if (
                (session->httpURI.numBytes == 12) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/pair-verify", 12)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                if (!session->securitySession.isSecured) {
                    handle_pairing_data(session, HAPSessionHandlePairVerifyWrite, HAPSessionHandlePairVerifyRead);
                } else {
                    HAPLog(&logObject, "Rejected POST /pair-verify: Only non-secure access is supported.");
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                }
            } else {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
            }
        } else if (
                (session->httpURI.numBytes == 9) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/pairings", 9)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        handle_pairing_data(session, HAPSessionHandlePairingsWrite, HAPSessionHandlePairingsRead);
                    } else {
                        HAPLog(&logObject, "Rejected POST /pairings: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            } else {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
                    } else {
                        HAPLog(&logObject, "Rejected request for /pairings: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            }
        } else if (
                (session->httpURI.numBytes == 15) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/secure-message", 15)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    handle_secure_message(session);
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            } else {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            }
        } else if (
                (session->httpURI.numBytes == 7) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/config", 7)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        HAPLog(&logObject, "Rejected POST /config: Session is not transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ResourceNotFound);
                    } else {
                        HAPLog(&logObject, "Rejected POST /config: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            } else {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
                    } else {
                        HAPLog(&logObject, "Rejected request for /config: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            }
        } else if (
                (session->httpURI.numBytes == 11) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/configured", 11)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                HAPLog(&logObject, "Received unexpected /configured on _hap._tcp endpoint. Replying with success.");
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_NoContent);
            } else {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
            }
        } else if (
                (session->httpURI.numBytes == 12) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/accessories", 12)) {
            if ((session->httpMethod.numBytes == 3) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "GET", 3)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        get_accessories(session);
                    } else {
                        HAPLog(&logObject, "Rejected GET /accessories: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(
                            &session->outboundBuffer,
                            kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequiredWithStatus);
                }
            } else {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
                    } else {
                        HAPLog(&logObject, "Rejected request for /accessories: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            }
        } else if (
                (session->httpURI.numBytes >= 16) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/characteristics", 16)) {
            if ((session->httpMethod.numBytes == 3) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "GET", 3)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        get_characteristics(session);
                    } else {
                        HAPLog(&logObject, "Rejected GET /characteristics: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(
                            &session->outboundBuffer,
                            kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequiredWithStatus);
                }
            } else if (
                    (session->httpMethod.numBytes == 3) &&
                    HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "PUT", 3)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        put_characteristics(session);
                    } else {
                        HAPLog(&logObject, "Rejected PUT /characteristics: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(
                            &session->outboundBuffer,
                            kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequiredWithStatus);
                }
            } else {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
                    } else {
                        HAPLog(&logObject, "Rejected request for /characteristics: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            }
        } else if (
                (session->httpURI.numBytes == 8) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/prepare", 8)) {
            if ((session->httpMethod.numBytes == 3) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "PUT", 3)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        put_prepare(session);
                    } else {
                        HAPLog(&logObject, "Rejected PUT /prepare: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(
                            &session->outboundBuffer,
                            kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequiredWithStatus);
                }
            } else {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
                    } else {
                        HAPLog(&logObject, "Rejected request for /prepare: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            }
        } else if (
                (session->httpURI.numBytes == 9) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpURI.bytes), "/resource", 9)) {
            if ((session->httpMethod.numBytes == 4) &&
                HAPRawBufferAreEqual(HAPNonnull(session->httpMethod.bytes), "POST", 4)) {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        post_resource(session);
                    } else {
                        HAPLog(&logObject, "Rejected POST /resource: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(
                            &session->outboundBuffer,
                            kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequiredWithStatus);
                }
            } else {
                if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                    if (!HAPSessionIsTransient(&session->securitySession.session)) {
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_MethodNotAllowed);
                    } else {
                        HAPLog(&logObject, "Rejected request for /resource: Session is transient.");
                        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                    }
                } else {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
                }
            }
        } else {
            HAPLogBuffer(&logObject, session->httpURI.bytes, session->httpURI.numBytes, "Unknown endpoint accessed.");
            if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
                if (!HAPSessionIsTransient(&session->securitySession.session)) {
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ResourceNotFound);
                } else {
                    HAPLog(&logObject, "Rejected request for unknown endpoint: Session is transient.");
                    write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_BadRequest);
                }
            } else {
                write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_ConnectionAuthorizationRequired);
            }
        }
    }
}

static void handle_http(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);

    size_t content_length;
    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->httpReaderPosition <= session->inboundBuffer.position);
    HAPAssert(session->httpReader.state == util_HTTP_READER_STATE_DONE);
    HAPAssert(!session->httpParserError);
    if (session->httpContentLength.isDefined) {
        content_length = session->httpContentLength.value;
    } else {
        content_length = 0;
    }
    if ((content_length <= session->inboundBuffer.position) &&
        (session->httpReaderPosition <= session->inboundBuffer.position - content_length)) {
        HAPLogBufferDebug(
                &logObject,
                session->inboundBuffer.data,
                session->httpReaderPosition + content_length,
                "session:%p:>",
                (const void*) session);
        handle_http_request(session);
        HAPIPByteBufferShiftLeft(&session->inboundBuffer, session->httpReaderPosition + content_length);
        switch (session->inProgress.state) {
        case kHAPIPSessionInProgressState_None:
            output(session);
            break;
        case kHAPIPSessionInProgressState_GetAccessories:
            // Session is already prepared for writing
            HAPAssert(session->outboundBuffer.data);
            HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
            HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);
            HAPAssert(session->state == kHAPIPSessionState_Writing);
            break;
        default:
            break;
        }
    }
}

static void update_token(struct util_http_reader* r, char** token, size_t* length) {
    HAPAssert(r);
    HAPAssert(token);
    HAPAssert(length);

    if (!*token) {
        *token = r->result_token;
        *length = r->result_length;
    } else if (r->result_token) {
        HAPAssert(&(*token)[*length] == r->result_token);
        *length += r->result_length;
    }
}

static void read_http_content_length(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);

    size_t i;
    int overflow;
    unsigned int v;

    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->httpReaderPosition <= session->inboundBuffer.position);
    HAPAssert(session->httpReader.state == util_HTTP_READER_STATE_COMPLETED_HEADER_VALUE);
    HAPAssert(!session->httpParserError);
    i = 0;
    while ((i < session->httpHeaderFieldValue.numBytes) &&
           ((session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_Space) ||
            (session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_HorizontalTab))) {
        // Skip whitespace.
        i++;
    }
    HAPAssert(
            (i == session->httpHeaderFieldValue.numBytes) ||
            ((i < session->httpHeaderFieldValue.numBytes) &&
             (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_Space) &&
             (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_HorizontalTab)));
    if ((i < session->httpHeaderFieldValue.numBytes) && ('0' <= session->httpHeaderFieldValue.bytes[i]) &&
        (session->httpHeaderFieldValue.bytes[i] <= '9') && !session->httpContentLength.isDefined) {
        overflow = 0;
        session->httpContentLength.value = 0;
        do {
            v = (unsigned int) (session->httpHeaderFieldValue.bytes[i] - '0');
            if (session->httpContentLength.value <= (SIZE_MAX - v) / 10) {
                session->httpContentLength.value = session->httpContentLength.value * 10 + v;
                i++;
            } else {
                overflow = 1;
            }
        } while (!overflow && (i < session->httpHeaderFieldValue.numBytes) &&
                 ('0' <= session->httpHeaderFieldValue.bytes[i]) && (session->httpHeaderFieldValue.bytes[i] <= '9'));
        HAPAssert(
                overflow || (i == session->httpHeaderFieldValue.numBytes) ||
                ((i < session->httpHeaderFieldValue.numBytes) &&
                 ((session->httpHeaderFieldValue.bytes[i] < '0') || (session->httpHeaderFieldValue.bytes[i] > '9'))));
        if (!overflow) {
            while ((i < session->httpHeaderFieldValue.numBytes) &&
                   ((session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_Space) ||
                    (session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_HorizontalTab))) {
                i++;
            }
            HAPAssert(
                    (i == session->httpHeaderFieldValue.numBytes) ||
                    ((i < session->httpHeaderFieldValue.numBytes) &&
                     (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_Space) &&
                     (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_HorizontalTab)));
            if (i == session->httpHeaderFieldValue.numBytes) {
                session->httpContentLength.isDefined = true;
            } else {
                session->httpParserError = true;
            }
        } else {
            session->httpParserError = true;
        }
    } else {
        session->httpParserError = true;
    }
}

static void read_http_content_type(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);

    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->httpReaderPosition <= session->inboundBuffer.position);
    HAPAssert(session->httpReader.state == util_HTTP_READER_STATE_COMPLETED_HEADER_VALUE);
    HAPAssert(!session->httpParserError);

    size_t i = 0;
    while ((i < session->httpHeaderFieldValue.numBytes) &&
           ((session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_Space) ||
            (session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_HorizontalTab))) {
        // Skip whitespace.
        i++;
    }
    HAPAssert(
            (i == session->httpHeaderFieldValue.numBytes) ||
            ((i < session->httpHeaderFieldValue.numBytes) &&
             (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_Space) &&
             (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_HorizontalTab)));
    if ((i < session->httpHeaderFieldValue.numBytes)) {
        session->httpContentType = kHAPIPAccessoryServerContentType_Unknown;

#define TryAssignContentType(contentType, contentTypeString) \
    do { \
        size_t numContentTypeStringBytes = sizeof(contentTypeString) - 1; \
        if (session->httpHeaderFieldValue.numBytes - i >= numContentTypeStringBytes && \
            HAPRawBufferAreEqual( \
                    &session->httpHeaderFieldValue.bytes[i], (contentTypeString), numContentTypeStringBytes)) { \
            session->httpContentType = (contentType); \
            i += numContentTypeStringBytes; \
        } \
    } while (0)

        // Check longer header values first if multiple have the same prefix.
        TryAssignContentType(kHAPIPAccessoryServerContentType_Application_HAPJSON, "application/hap+json");
        TryAssignContentType(kHAPIPAccessoryServerContentType_Application_OctetStream, "application/octet-stream");
        TryAssignContentType(kHAPIPAccessoryServerContentType_Application_PairingTLV8, "application/pairing+tlv8");

#undef TryAssignContentType

        while ((i < session->httpHeaderFieldValue.numBytes) &&
               ((session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_Space) ||
                (session->httpHeaderFieldValue.bytes[i] == kHAPIPAccessoryServerCharacter_HorizontalTab))) {
            i++;
        }
        HAPAssert(
                (i == session->httpHeaderFieldValue.numBytes) ||
                ((i < session->httpHeaderFieldValue.numBytes) &&
                 (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_Space) &&
                 (session->httpHeaderFieldValue.bytes[i] != kHAPIPAccessoryServerCharacter_HorizontalTab)));
        if (i != session->httpHeaderFieldValue.numBytes) {
            HAPLogBuffer(
                    &logObject,
                    session->httpHeaderFieldValue.bytes,
                    session->httpHeaderFieldValue.numBytes,
                    "Unknown Content-Type.");
            session->httpContentType = kHAPIPAccessoryServerContentType_Unknown;
        }
    } else {
        session->httpParserError = true;
    }
}

static void read_http(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);

    struct util_http_reader* r;

    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->httpReaderPosition <= session->inboundBuffer.position);
    HAPAssert(!session->httpParserError);
    r = &session->httpReader;
    bool hasContentLength = false;
    bool hasContentType = false;
    do {
        session->httpReaderPosition += util_http_reader_read(
                r,
                &session->inboundBuffer.data[session->httpReaderPosition],
                session->inboundBuffer.position - session->httpReaderPosition);
        switch (r->state) {
            case util_HTTP_READER_STATE_READING_METHOD:
            case util_HTTP_READER_STATE_COMPLETED_METHOD: {
                update_token(r, &session->httpMethod.bytes, &session->httpMethod.numBytes);
            } break;
            case util_HTTP_READER_STATE_READING_URI:
            case util_HTTP_READER_STATE_COMPLETED_URI: {
                update_token(r, &session->httpURI.bytes, &session->httpURI.numBytes);
            } break;
            case util_HTTP_READER_STATE_READING_HEADER_NAME:
            case util_HTTP_READER_STATE_COMPLETED_HEADER_NAME: {
                update_token(r, &session->httpHeaderFieldName.bytes, &session->httpHeaderFieldName.numBytes);
            } break;
            case util_HTTP_READER_STATE_READING_HEADER_VALUE: {
                update_token(r, &session->httpHeaderFieldValue.bytes, &session->httpHeaderFieldValue.numBytes);
            } break;
            case util_HTTP_READER_STATE_COMPLETED_HEADER_VALUE: {
                update_token(r, &session->httpHeaderFieldValue.bytes, &session->httpHeaderFieldValue.numBytes);
                HAPAssert(session->httpHeaderFieldName.bytes);
                if ((session->httpHeaderFieldName.numBytes == 14) &&
                    (session->httpHeaderFieldName.bytes[0] == 'C' || session->httpHeaderFieldName.bytes[0] == 'c') &&
                    (session->httpHeaderFieldName.bytes[1] == 'O' || session->httpHeaderFieldName.bytes[1] == 'o') &&
                    (session->httpHeaderFieldName.bytes[2] == 'N' || session->httpHeaderFieldName.bytes[2] == 'n') &&
                    (session->httpHeaderFieldName.bytes[3] == 'T' || session->httpHeaderFieldName.bytes[3] == 't') &&
                    (session->httpHeaderFieldName.bytes[4] == 'E' || session->httpHeaderFieldName.bytes[4] == 'e') &&
                    (session->httpHeaderFieldName.bytes[5] == 'N' || session->httpHeaderFieldName.bytes[5] == 'n') &&
                    (session->httpHeaderFieldName.bytes[6] == 'T' || session->httpHeaderFieldName.bytes[6] == 't') &&
                    (session->httpHeaderFieldName.bytes[7] == '-') &&
                    (session->httpHeaderFieldName.bytes[8] == 'L' || session->httpHeaderFieldName.bytes[8] == 'l') &&
                    (session->httpHeaderFieldName.bytes[9] == 'E' || session->httpHeaderFieldName.bytes[9] == 'e') &&
                    (session->httpHeaderFieldName.bytes[10] == 'N' || session->httpHeaderFieldName.bytes[10] == 'n') &&
                    (session->httpHeaderFieldName.bytes[11] == 'G' || session->httpHeaderFieldName.bytes[11] == 'g') &&
                    (session->httpHeaderFieldName.bytes[12] == 'T' || session->httpHeaderFieldName.bytes[12] == 't') &&
                    (session->httpHeaderFieldName.bytes[13] == 'H' || session->httpHeaderFieldName.bytes[13] == 'h')) {
                    if (hasContentLength) {
                        HAPLog(&logObject, "Request has multiple Content-Length headers.");
                        session->httpParserError = true;
                    } else {
                        hasContentLength = true;
                        read_http_content_length(session);
                    }
                } else if (
                        (session->httpHeaderFieldName.numBytes == 12) &&
                        (session->httpHeaderFieldName.bytes[0] == 'C' ||
                         session->httpHeaderFieldName.bytes[0] == 'c') &&
                        (session->httpHeaderFieldName.bytes[1] == 'O' ||
                         session->httpHeaderFieldName.bytes[1] == 'o') &&
                        (session->httpHeaderFieldName.bytes[2] == 'N' ||
                         session->httpHeaderFieldName.bytes[2] == 'n') &&
                        (session->httpHeaderFieldName.bytes[3] == 'T' ||
                         session->httpHeaderFieldName.bytes[3] == 't') &&
                        (session->httpHeaderFieldName.bytes[4] == 'E' ||
                         session->httpHeaderFieldName.bytes[4] == 'e') &&
                        (session->httpHeaderFieldName.bytes[5] == 'N' ||
                         session->httpHeaderFieldName.bytes[5] == 'n') &&
                        (session->httpHeaderFieldName.bytes[6] == 'T' ||
                         session->httpHeaderFieldName.bytes[6] == 't') &&
                        (session->httpHeaderFieldName.bytes[7] == '-') &&
                        (session->httpHeaderFieldName.bytes[8] == 'T' ||
                         session->httpHeaderFieldName.bytes[8] == 't') &&
                        (session->httpHeaderFieldName.bytes[9] == 'Y' ||
                         session->httpHeaderFieldName.bytes[9] == 'y') &&
                        (session->httpHeaderFieldName.bytes[10] == 'P' ||
                         session->httpHeaderFieldName.bytes[10] == 'p') &&
                        (session->httpHeaderFieldName.bytes[11] == 'E' ||
                         session->httpHeaderFieldName.bytes[11] == 'e')) {
                    if (hasContentType) {
                        HAPLog(&logObject, "Request has multiple Content-Type headers.");
                        session->httpParserError = true;
                    } else {
                        hasContentType = true;
                        read_http_content_type(session);
                    }
                }
                session->httpHeaderFieldName.bytes = NULL;
                session->httpHeaderFieldValue.bytes = NULL;
            } break;
            default: {
            } break;
        }
    } while ((session->httpReaderPosition < session->inboundBuffer.position) &&
             (r->state != util_HTTP_READER_STATE_DONE) && (r->state != util_HTTP_READER_STATE_ERROR) &&
             !session->httpParserError);
    HAPAssert(
            (session->httpReaderPosition == session->inboundBuffer.position) ||
            ((session->httpReaderPosition < session->inboundBuffer.position) &&
             ((r->state == util_HTTP_READER_STATE_DONE) || (r->state == util_HTTP_READER_STATE_ERROR) ||
              session->httpParserError)));
}

static void handle_input(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);

    int r;

    HAPAssert(session->inboundBuffer.data);
    HAPAssert(session->inboundBuffer.position <= session->inboundBuffer.limit);
    HAPAssert(session->inboundBuffer.limit <= session->inboundBuffer.capacity);
    HAPAssert(session->inboundBufferMark <= session->inboundBuffer.position);
    session->inboundBuffer.limit = session->inboundBuffer.position;
    if (HAPSessionIsSecured(&session->securitySession.session)) {
        // TODO Should be moved to handle_completed_output, maybe.
        if (!session->securitySession.isSecured) {
            HAPLogDebug(&logObject, "Established HAP security session.");
            session->securitySession.isSecured = true;
        }
        session->inboundBuffer.position = session->inboundBufferMark;
        r = HAPIPSecurityProtocolDecryptData(
                HAPNonnull(session->server), &session->securitySession.session, &session->inboundBuffer);
    } else {
        HAPAssert(!session->securitySession.isSecured);
        r = 0;
    }
    if (r == 0) {
        read_http(session);
        if ((session->httpReader.state == util_HTTP_READER_STATE_ERROR) || session->httpParserError) {
            log_protocol_error(
                    kHAPLogType_Info, "Unexpected request.", &session->inboundBuffer, __func__, HAP_FILE, __LINE__);
            CloseSession(session);
        } else {
            if (session->httpReader.state == util_HTTP_READER_STATE_DONE) {
                handle_http(session);
            }
            session->inboundBufferMark = session->inboundBuffer.position;
            session->inboundBuffer.position = session->inboundBuffer.limit;
            session->inboundBuffer.limit = session->inboundBuffer.capacity;
            if ((session->state == kHAPIPSessionState_Reading) &&
                (session->inboundBuffer.position == session->inboundBuffer.limit)) {
                log_protocol_error(
                        kHAPLogType_Info,
                        "Unexpected request. Closing connection (inbound buffer too small).",
                        &session->inboundBuffer,
                        __func__,
                        HAP_FILE,
                        __LINE__);
                CloseSession(session);
            }
        }
    } else {
        HAPAssert(r == -1);
        HAPLog(&logObject, "Decryption error.");
        CloseSession(session);
    }
}

static void finsh_write_event_notifications(
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContextRef* contexts,
        size_t numContexts) {
    size_t content_length = HAPIPAccessoryProtocolGetNumEventNotificationBytes(
            HAPNonnull(session->server), contexts, numContexts);

    HAPAssert(session->outboundBuffer.data);
    HAPAssert(session->outboundBuffer.position <= session->outboundBuffer.limit);
    HAPAssert(session->outboundBuffer.limit <= session->outboundBuffer.capacity);
    size_t mark = session->outboundBuffer.position;
    HAPError err = HAPIPByteBufferAppendStringWithFormat(
            &session->outboundBuffer,
            "EVENT/1.0 200 OK\r\n"
            "Content-Type: application/hap+json\r\n"
            "Content-Length: %zu\r\n\r\n",
            content_length);
    if (err) {
        HAPAssert(err == kHAPError_OutOfResources);
        HAPLog(&logObject, "Invalid configuration (outbound buffer too small).");
        HAPFatalError();
    }
    if (content_length <= session->outboundBuffer.limit - session->outboundBuffer.position) {
        mark = session->outboundBuffer.position;
        err = HAPIPAccessoryProtocolGetEventNotificationBytes(
                HAPNonnull(session->server),
                session->contexts,
                numContexts,
                &session->outboundBuffer);
        HAPAssert(!err && (session->outboundBuffer.position - mark == content_length));
        HAPIPByteBufferFlip(&session->outboundBuffer);
        HAPLogBufferDebug(
                &logObject,
                session->outboundBuffer.data,
                session->outboundBuffer.limit,
                "session:%p:<",
                (const void*) session);
        if (session->securitySession.isSecured) {
            size_t encrypted_length = HAPIPSecurityProtocolGetNumEncryptedBytes(
                    session->outboundBuffer.limit - session->outboundBuffer.position);
            if (encrypted_length <= session->outboundBuffer.capacity - session->outboundBuffer.position) {
                HAPIPSecurityProtocolEncryptData(
                        HAPNonnull(session->server), &session->securitySession.session, &session->outboundBuffer);
                HAPAssert(encrypted_length == session->outboundBuffer.limit - session->outboundBuffer.position);
                session->state = kHAPIPSessionState_Writing;
            } else {
                HAPLog(&logObject, "Skipping event notifications (outbound buffer too small).");
                HAPIPByteBufferClear(&session->outboundBuffer);
            }
        } else {
            HAPAssert(kHAPIPAccessoryServer_SessionSecurityDisabled);
            HAP_DIAGNOSTIC_IGNORED_ICCARM(Pe111)
            session->state = kHAPIPSessionState_Writing;
            HAP_DIAGNOSTIC_RESTORE_ICCARM(Pe111)
        }
    } else {
        HAPLog(&logObject, "Skipping event notifications (outbound buffer too small).");
        session->outboundBuffer.position = mark;
    }
}

void event_notification_timeout_timer(HAPPlatformTimerRef timer, void* _Nullable context) {
    HAPIPSessionDescriptor* session = context;

    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->inProgress.state == kHAPIPSessionInProgressState_EventNotifications);
    HAPPrecondition(session->inProgress.numContexts != 0);

    HAPAccessoryServer* server = (HAPAccessoryServer*)session->server;
    session->inProgress.timer = 0;

    for (size_t i = 0; i < session->numContexts; i++) {
        HAPIPCharacteristicContext* context = (HAPIPCharacteristicContext*) &session->contexts[i];
        if (context->status == kHAPError_InProgress) {
            context->status = kHAPError_Busy;
        }
    }
    session->inProgress.numContexts = 0;
    session->inProgress.state = kHAPIPSessionInProgressState_None;
    finsh_write_event_notifications(session, session->contexts, session->numContexts);
    if (session->state == kHAPIPSessionState_Writing) {
        HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = false, .hasSpaceAvailable = true };
        HAPPlatformTCPStreamUpdateInterests(
                HAPNonnull(server->platform.ip.tcpStreamManager),
                session->tcpStream,
                interests,
                HandleTCPStreamEvent,
                session);
    }
}

static void write_event_notifications(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(session->state == kHAPIPSessionState_Reading);
    HAPPrecondition(session->inProgress.state == kHAPIPSessionInProgressState_None);
    HAPPrecondition(session->inProgress.numContexts == 0);
    HAPPrecondition(session->inboundBuffer.position == 0);
    HAPPrecondition(session->numEventNotificationFlags > 0);
    HAPPrecondition(session->numEventNotificationFlags <= session->numEventNotifications);
    HAPPrecondition(session->numEventNotifications <= session->maxEventNotifications);

    if (session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled) {
        HAPTime clock_now_ms = HAPPlatformClockGetCurrent();
        HAPAssert(clock_now_ms >= session->eventNotificationStamp);
        bool _notifyNow = (clock_now_ms - session->eventNotificationStamp) >=
            kHAPIPAccessoryServer_MaxEventNotificationDelay;
        if (_notifyNow) {
            session->eventNotificationStamp = clock_now_ms;
        }

        session->numContexts = 0;

        for (size_t i = 0; i < session->numEventNotifications; i++) {
            HAPIPEventNotification* eventNotification = (HAPIPEventNotification*) &session->eventNotifications[i];
            if (eventNotification->flag) {
                bool notifyNow = _notifyNow;
                if (!notifyNow) {
                    // Network-based notifications must be coalesced by the accessory using a delay of no less than
                    // 1 second. The exception to this rule includes notifications for the following characteristics
                    // which must be delivered immediately.
                    // See HomeKit Accessory Protocol Specification R14
                    // Section 6.8 Notifications
                    const HAPCharacteristic* characteristic_;
                    const HAPService* service;
                    const HAPAccessory* accessory;
                    get_db_ctx(
                            session->server,
                            eventNotification->aid,
                            eventNotification->iid,
                            &characteristic_,
                            &service,
                            &accessory);
                    HAPAssert(accessory);
                    HAPAssert(service);
                    HAPAssert(characteristic_);
                    const HAPBaseCharacteristic* characteristic = characteristic_;
                    notifyNow = HAPUUIDAreEqual(
                            characteristic->characteristicType, &kHAPCharacteristicType_ProgrammableSwitchEvent);
                    if (notifyNow) {
                        HAPLogCharacteristicDebug(
                                &logObject,
                                characteristic_,
                                service,
                                accessory,
                                "Characteristic whitelisted to bypassing notification coalescing requirement.");
                    }
                }
                if (notifyNow) {
                    HAPAssert(session->numContexts < session->maxContexts);
                    HAPIPCharacteristicContext* context =
                            (HAPIPCharacteristicContext*) &session->contexts[session->numContexts];
                    HAPRawBufferZero(context, sizeof(*context));
                    context->aid = eventNotification->aid;
                    context->iid = eventNotification->iid;
                    session->numContexts++;
                    eventNotification->flag = false;
                    HAPAssert(session->numEventNotificationFlags > 0);
                    session->numEventNotificationFlags--;
                }
            }
        }

        if (session->numContexts > 0) {
            bool mutliStatus = false;
            HAPIPByteBufferClear(&session->scratchBuffer);
            session->inProgress.numContexts = handle_characteristic_read_requests(
                    session,
                    kHAPIPSessionContext_EventNotification,
                    session->contexts,
                    session->numContexts,
                    &mutliStatus,
                    &session->scratchBuffer);
            if (session->inProgress.numContexts) {
                session->inProgress.state = kHAPIPSessionInProgressState_EventNotifications;
                HAPAssert(session->inProgress.timer == 0);
                HAPError err = HAPPlatformTimerRegister(
                        &session->inProgress.timer,
                        clock_now_ms + kHAPIPAccessoryServer_EventNotificationTimeout,
                        event_notification_timeout_timer,
                        session);
                if (err) {
                    HAPLog(&logObject, "Not enough resources to schedule event notification timeout timer!");
                    HAPFatalError();
                }
            } else {
                finsh_write_event_notifications(session, session->contexts, session->numContexts);
            }
            if (session->state == kHAPIPSessionState_Writing) {
                HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = false, .hasSpaceAvailable = true };
                HAPPlatformTCPStreamUpdateInterests(
                        HAPNonnull(server->platform.ip.tcpStreamManager),
                        session->tcpStream,
                        interests,
                        HandleTCPStreamEvent,
                        session);
            }
        }
    } else {
        for (size_t i = 0; i < session->numEventNotifications; i++) {
            HAPIPEventNotification* eventNotification = (HAPIPEventNotification*) &session->eventNotifications[i];
            if (eventNotification->flag) {
                eventNotification->flag = false;
                HAPAssert(session->numEventNotificationFlags > 0);
                session->numEventNotificationFlags--;
            }
        }
        HAPAssert(session->numEventNotificationFlags == 0);
        session->eventNotificationStamp = HAPPlatformClockGetCurrent();
    }
}

static void handle_io_progression(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;

    if ((session->state == kHAPIPSessionState_Reading) && (session->inboundBuffer.position == 0)) {
        if (server->ip.state == kHAPIPAccessoryServerState_Stopping) {
            CloseSession(session);
        } else {
            HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Running);
            if (session->numEventNotificationFlags > 0) {
                schedule_event_notifications(session->server);
            }
        }
    }
    if (session->tcpStreamIsOpen) {
        HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = (session->state == kHAPIPSessionState_Reading),
                                                .hasSpaceAvailable = (session->state == kHAPIPSessionState_Writing) };
        if ((session->state == kHAPIPSessionState_Reading) || (session->state == kHAPIPSessionState_Writing)) {
            HAPPlatformTCPStreamUpdateInterests(
                    HAPNonnull(server->platform.ip.tcpStreamManager),
                    session->tcpStream,
                    interests,
                    HandleTCPStreamEvent,
                    session);
        } else {
            HAPPlatformTCPStreamUpdateInterests(
                    HAPNonnull(server->platform.ip.tcpStreamManager), session->tcpStream, interests, NULL, session);
        }
    } else {
        HAPAssert(server->ip.garbageCollectionTimer);
    }
}

static void handle_output_completion(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;

    HAPAssert(session->state == kHAPIPSessionState_Writing);
    if (session->securitySession.isOpen && session->securitySession.receivedConfig) {
        HAPLogDebug(&logObject, "Completed sending of Wi-Fi configuration response.");

        HAPAssert(session->tcpStreamIsOpen);
        HAPPlatformTCPStreamCloseOutput(HAPNonnull(server->platform.ip.tcpStreamManager), session->tcpStream);
    }
    session->state = kHAPIPSessionState_Reading;
    prepare_reading_request(session);
    if (session->inboundBuffer.position != 0) {
        handle_input(session);
    }
}

static void WriteOutboundData(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPPrecondition(session->tcpStreamIsOpen);

    HAPError err;

    HAPIPByteBuffer* b;
    b = &session->outboundBuffer;
    HAPAssert(b->data);
    HAPAssert(b->position <= b->limit);
    HAPAssert(b->limit <= b->capacity);

    size_t numBytes;
    err = HAPPlatformTCPStreamWrite(
            HAPNonnull(server->platform.ip.tcpStreamManager),
            session->tcpStream,
            /* bytes: */ &b->data[b->position],
            /* maxBytes: */ b->limit - b->position,
            &numBytes);

    if (err == kHAPError_Unknown) {
        log_result(
                kHAPLogType_Error,
                "error:Function 'HAPPlatformTCPStreamWrite' failed.",
                err,
                __func__,
                HAP_FILE,
                __LINE__);
        CloseSession(session);
        return;
    } else if (err == kHAPError_Busy) {
        return;
    }

    HAPAssert(!err);
    if (numBytes == 0) {
        HAPLogDebug(&logObject, "error:Function 'HAPPlatformTCPStreamWrite' failed: 0 bytes written.");
        CloseSession(session);
        return;
    } else {
        HAPAssert(numBytes <= b->limit - b->position);
        b->position += numBytes;
        if (b->position == b->limit) {
            if (session->securitySession.isSecured &&
                !HAPSessionIsSecured(&session->securitySession.session)) {
                HAPLogDebug(&logObject, "Pairing removed, closing session.");
                CloseSession(session);
            } else if (session->inProgress.state == kHAPIPSessionInProgressState_GetAccessories) {
                handle_accessory_serialization(session);
            } else {
                HAPIPByteBufferClear(b);
                handle_output_completion(session);
            }
        }
    }
}

static void handle_input_closed(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;

    HAPLogDebug(&logObject, "session:%p:input closed", (const void*) session);

    if (session->securitySession.isOpen && session->securitySession.receivedConfig) {
        HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Stopping);
    } else {
        CloseSession(session);
    }
}

static void ReadInboundData(HAPIPSessionDescriptor* session) {
    HAPPrecondition(session);
    HAPPrecondition(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPAssert(session->tcpStreamIsOpen);

    HAPError err;

    HAPIPByteBuffer* b;
    b = &session->inboundBuffer;
    HAPAssert(b->data);
    HAPAssert(b->position <= b->limit);
    HAPAssert(b->limit <= b->capacity);

    size_t numBytes;
    err = HAPPlatformTCPStreamRead(
            HAPNonnull(server->platform.ip.tcpStreamManager),
            session->tcpStream,
            /* bytes: */ &b->data[b->position],
            /* maxBytes: */ b->limit - b->position,
            &numBytes);

    if (err == kHAPError_Unknown) {
        log_result(
                kHAPLogType_Error,
                "error:Function 'HAPPlatformTCPStreamRead' failed.",
                err,
                __func__,
                HAP_FILE,
                __LINE__);
        CloseSession(session);
        return;
    } else if (err == kHAPError_Busy) {
        return;
    }

    HAPAssert(!err);
    if (numBytes == 0) {
        handle_input_closed(session);
    } else {
        HAPAssert(numBytes <= b->limit - b->position);
        b->position += numBytes;
        if (session->inProgress.state == kHAPIPSessionInProgressState_None) {
            handle_input(session);
        }
    }
}

static void HandleTCPStreamEvent(
        HAPPlatformTCPStreamManagerRef tcpStreamManager_,
        HAPPlatformTCPStreamRef tcpStream,
        HAPPlatformTCPStreamEvent event,
        void* _Nullable context) {
    HAPAssert(context);
    HAPIPSessionDescriptor* session = context;
    HAPAssert(session->server);
    HAPAccessoryServer* server = (HAPAccessoryServer*) session->server;
    HAPAssert(tcpStreamManager_ == server->platform.ip.tcpStreamManager);
    HAPAssert(session->tcpStream == tcpStream);
    HAPAssert(session->tcpStreamIsOpen);

    HAPTime clock_now_ms = HAPPlatformClockGetCurrent();

    if (event.hasBytesAvailable) {
        HAPAssert(!event.hasSpaceAvailable);
        HAPAssert(session->state == kHAPIPSessionState_Reading);
        session->stamp = clock_now_ms;
        ReadInboundData(session);
        handle_io_progression(session);
    }

    if (event.hasSpaceAvailable) {
        HAPAssert(!event.hasBytesAvailable);
        HAPAssert(session->state == kHAPIPSessionState_Writing);
        session->stamp = clock_now_ms;
        WriteOutboundData(session);
        handle_io_progression(session);
    }
}

static void HandlePendingTCPStream(HAPPlatformTCPStreamManagerRef tcpStreamManager, void* _Nullable context) {
    HAPPrecondition(context);
    HAPAccessoryServerRef* server_ = context;
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;
    HAPAssert(tcpStreamManager == server->platform.ip.tcpStreamManager);

    HAPError err;

    HAPPlatformTCPStreamRef tcpStream;
    err = HAPPlatformTCPStreamManagerAcceptTCPStream(HAPNonnull(server->platform.ip.tcpStreamManager), &tcpStream);
    if (err) {
        log_result(
                kHAPLogType_Error,
                "error:Function 'HAPPlatformTCPStreamManagerAcceptTCPStream' failed.",
                err,
                __func__,
                HAP_FILE,
                __LINE__);
        return;
    }

    // Find free IP session.
    HAPIPSession* ipSession = NULL;
    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
        HAPIPSessionDescriptor* descriptor = (HAPIPSessionDescriptor*) &server->ip.storage->sessions[i].descriptor;
        if (!descriptor->server) {
            ipSession = &server->ip.storage->sessions[i];
            break;
        }
    }
    if (!ipSession) {
        HAPLog(&logObject,
               "Failed to allocate session."
               " (Number of supported accessory server sessions should be consistent with"
               " the maximum number of concurrent streams supported by TCP stream manager.)");
        HAPPlatformTCPStreamClose(HAPNonnull(server->platform.ip.tcpStreamManager), tcpStream);
        return;
    }

    HAPIPSessionDescriptor* t = (HAPIPSessionDescriptor*) &ipSession->descriptor;
    HAPRawBufferZero(t, sizeof(*t));
    t->server = server_;
    t->tcpStream = tcpStream;
    t->tcpStreamIsOpen = true;
    t->state = kHAPIPSessionState_Idle;
    t->stamp = HAPPlatformClockGetCurrent();
    t->securitySession.isOpen = false;
    t->securitySession.isSecured = false;
    HAPIPByteBufferInit(&t->inboundBuffer, ipSession->inboundBuffer.bytes, ipSession->inboundBuffer.numBytes);
    HAPIPByteBufferInit(&t->outboundBuffer, ipSession->outboundBuffer.bytes, ipSession->outboundBuffer.numBytes);
    HAPIPByteBufferInit(&t->scratchBuffer, ipSession->scratchBuffer.bytes, ipSession->scratchBuffer.numBytes);
    t->contexts = ipSession->contexts;
    t->maxContexts = ipSession->numContexts;
    t->eventNotifications = ipSession->eventNotifications;
    t->maxEventNotifications = ipSession->numEventNotifications;
    OpenSecuritySession(t);
    t->state = kHAPIPSessionState_Reading;
    prepare_reading_request(t);
    HAPAssert(t->tcpStreamIsOpen);
    HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = true, .hasSpaceAvailable = false };
    HAPPlatformTCPStreamUpdateInterests(
            HAPNonnull(server->platform.ip.tcpStreamManager), t->tcpStream, interests, HandleTCPStreamEvent, t);

    RegisterSession(t);

    HAPLogDebug(&logObject, "session:%p:accepted", (const void*) t);
}

static void engine_init(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    HAPLogDebug(
            &logObject,
            "Storage configuration: ipAccessoryServerStorage = %lu",
            (unsigned long) sizeof *server->ip.storage);
    HAPLogDebug(
            &logObject, "Storage configuration: numSessions = %lu", (unsigned long) server->ip.storage->numSessions);
    HAPLogDebug(
            &logObject,
            "Storage configuration: sessions = %lu",
            (unsigned long) (server->ip.storage->numSessions * sizeof(HAPIPSession)));
    for (size_t i = 0; i < server->ip.storage->numSessions;) {
        size_t j;
        for (j = i + 1; j < server->ip.storage->numSessions; j++) {
            if (server->ip.storage->sessions[j].inboundBuffer.numBytes !=
                        server->ip.storage->sessions[i].inboundBuffer.numBytes ||
                server->ip.storage->sessions[j].outboundBuffer.numBytes !=
                        server->ip.storage->sessions[i].outboundBuffer.numBytes ||
                server->ip.storage->sessions[j].scratchBuffer.numBytes !=
                        server->ip.storage->sessions[i].scratchBuffer.numBytes ||
                server->ip.storage->sessions[j].numContexts !=
                        server->ip.storage->sessions[i].numContexts ||
                server->ip.storage->sessions[j].numEventNotifications !=
                        server->ip.storage->sessions[i].numEventNotifications) {
                break;
            }
        }
        if (i == j - 1) {
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu].inboundBuffer.numBytes = %lu",
                    (unsigned long) i,
                    (unsigned long) server->ip.storage->sessions[i].inboundBuffer.numBytes);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu].outboundBuffer.numBytes = %lu",
                    (unsigned long) i,
                    (unsigned long) server->ip.storage->sessions[i].outboundBuffer.numBytes);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu].scratchBuffer.numBytes = %lu",
                    (unsigned long) i,
                    (unsigned long) server->ip.storage->sessions[i].scratchBuffer.numBytes);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu].numContexts = %lu",
                    (unsigned long) i,
                    (unsigned long) server->ip.storage->sessions[i].numContexts);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu].contexts = %lu",
                    (unsigned long) i,
                    (unsigned long) (server->ip.storage->sessions[i].numContexts * sizeof(HAPIPCharacteristicContextRef)));
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu].numEventNotifications = %lu",
                    (unsigned long) i,
                    (unsigned long) server->ip.storage->sessions[i].numEventNotifications);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu].eventNotifications = %lu",
                    (unsigned long) i,
                    (unsigned long) (server->ip.storage->sessions[i].numEventNotifications * sizeof(HAPIPEventNotificationRef)));
        } else {
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu...%lu].inboundBuffer.numBytes = %lu",
                    (unsigned long) i,
                    (unsigned long) j - 1,
                    (unsigned long) server->ip.storage->sessions[i].inboundBuffer.numBytes);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu...%lu].outboundBuffer.numBytes = %lu",
                    (unsigned long) i,
                    (unsigned long) j - 1,
                    (unsigned long) server->ip.storage->sessions[i].outboundBuffer.numBytes);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu...%lu].scratchBuffer.numBytes = %lu",
                    (unsigned long) i,
                    (unsigned long) j - 1,
                    (unsigned long) server->ip.storage->sessions[i].scratchBuffer.numBytes);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu...%lu].numContexts = %lu",
                    (unsigned long) i,
                    (unsigned long) j - 1,
                    (unsigned long) server->ip.storage->sessions[i].numContexts);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu...%lu].contexts = %lu",
                    (unsigned long) i,
                    (unsigned long) j - 1,
                    (unsigned long) (server->ip.storage->sessions[i].numContexts * sizeof(HAPIPCharacteristicContextRef)));
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu...%lu].numEventNotifications = %lu",
                    (unsigned long) i,
                    (unsigned long) j - 1,
                    (unsigned long) server->ip.storage->sessions[i].numEventNotifications);
            HAPLogDebug(
                    &logObject,
                    "Storage configuration: sessions[%lu...%lu].eventNotifications = %lu",
                    (unsigned long) i,
                    (unsigned long) j - 1,
                    (unsigned long) (server->ip.storage->sessions[i].numEventNotifications * sizeof(HAPIPEventNotificationRef)));
        }
        i = j;
    }

    HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Undefined);

    server->ip.state = kHAPIPAccessoryServerState_Idle;
    server->ip.nextState = kHAPIPAccessoryServerState_Undefined;
}

HAP_RESULT_USE_CHECK
static HAPError engine_deinit(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Idle);

    server->ip.state = kHAPIPAccessoryServerState_Undefined;

    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
static HAPAccessoryServerState engine_get_state(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    switch (server->ip.state) {
        case kHAPIPAccessoryServerState_Undefined: {
            HAPPrecondition(false);
        } break;
        case kHAPIPAccessoryServerState_Idle: {
            return kHAPAccessoryServerState_Idle;
        }
        case kHAPIPAccessoryServerState_Running: {
            return kHAPAccessoryServerState_Running;
        }
        case kHAPIPAccessoryServerState_Stopping: {
            if (server->ip.nextState == kHAPIPAccessoryServerState_Running) {
                return kHAPAccessoryServerState_Running;
            } else {
                HAPAssert(server->ip.nextState == kHAPIPAccessoryServerState_Idle);
                return kHAPAccessoryServerState_Stopping;
            }
        }
    }

    HAPFatalError();
}

static void handle_server_state_transition_timer(HAPPlatformTimerRef timer, void* _Nullable context) {
    HAPPrecondition(context);
    HAPAccessoryServerRef* server_ = context;
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;
    (void) server;
    HAPPrecondition(timer == server->ip.stateTransitionTimer);
    server->ip.stateTransitionTimer = 0;

    HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Stopping);
    schedule_max_idle_time_timer(server_);
}

static void schedule_server_state_transition(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;
    (void) server;

    HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Stopping);

    HAPError err;

    if (!server->ip.stateTransitionTimer) {
        err = HAPPlatformTimerRegister(
                &server->ip.stateTransitionTimer, 0, handle_server_state_transition_timer, server_);
        if (err) {
            HAPLog(&logObject, "Not enough resources to schedule accessory server state transition!");
            HAPFatalError();
        }
        HAPAssert(server->ip.stateTransitionTimer);
    }
}

static void engine_start(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    HAPAssert(server->ip.state == kHAPIPAccessoryServerState_Idle);

    HAPLogDebug(&logObject, "Starting server engine.");

    server->ip.state = kHAPIPAccessoryServerState_Running;
    HAPAccessoryServerDelegateScheduleHandleUpdatedState(server_);

    HAPAssert(!HAPPlatformTCPStreamManagerIsListenerOpen(HAPNonnull(server->platform.ip.tcpStreamManager)));

    HAPPlatformTCPStreamManagerOpenListener(
            HAPNonnull(server->platform.ip.tcpStreamManager), HandlePendingTCPStream, server_);
    HAPAssert(HAPPlatformTCPStreamManagerIsListenerOpen(HAPNonnull(server->platform.ip.tcpStreamManager)));
    publish_homeKit_service(server_);
}

HAP_RESULT_USE_CHECK
static HAPError engine_stop(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    HAPLogDebug(&logObject, "Stopping server engine.");

    if (server->ip.state == kHAPIPAccessoryServerState_Running) {
        HAPAssert(server->ip.nextState == kHAPIPAccessoryServerState_Undefined);
        server->ip.state = kHAPIPAccessoryServerState_Stopping;
        server->ip.nextState = kHAPIPAccessoryServerState_Idle;
        HAPAccessoryServerDelegateScheduleHandleUpdatedState(server_);
        schedule_server_state_transition(server_);
    } else if (server->ip.state == kHAPIPAccessoryServerState_Stopping) {
        if (server->ip.nextState == kHAPIPAccessoryServerState_Running) {
            server->ip.nextState = kHAPIPAccessoryServerState_Idle;
        } else {
            HAPAssert(server->ip.nextState == kHAPIPAccessoryServerState_Idle);
        }
    }

    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
static HAPError engine_raise_event_on_session_(
        HAPAccessoryServerRef* server_,
        const HAPCharacteristic* characteristic_,
        const HAPService* service_,
        const HAPAccessory* accessory_,
        const HAPSessionRef* securitySession_) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    HAPPrecondition(characteristic_);
    HAPPrecondition(service_);
    HAPPrecondition(accessory_);

    HAPError err;

    size_t events_raised = 0;

    uint64_t aid = accessory_->aid;
    uint64_t iid = ((const HAPBaseCharacteristic*) characteristic_)->iid;

    for (size_t i = 0; i < server->ip.storage->numSessions; i++) {
        HAPIPSession* ipSession = &server->ip.storage->sessions[i];
        HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) &ipSession->descriptor;
        if (!session->server) {
            continue;
        }
        if (securitySession_ && (securitySession_ != &session->securitySession.session)) {
            continue;
        }
        if (HAPSessionIsTransient(&session->securitySession.session)) {
            HAPLogDebug(&logObject, "Not flagging event pending on transient session.");
            continue;
        }

        if (session->inProgress.state == kHAPIPSessionInProgressState_PutCharacteristics) {
            HAPIPCharacteristicContext *ctx = get_ctx_by_iid(
                    accessory_->aid,
                    ((HAPBaseCharacteristic*) characteristic_)->iid,
                    session->contexts,
                    session->numContexts);
            if (ctx && ctx->status == kHAPIPAccessoryServerStatusCode_InPorgress) {
                continue;
            }
        }

        if ((ipSession != server->ip.characteristicWriteRequestContext.ipSession) ||
            (characteristic_ != server->ip.characteristicWriteRequestContext.characteristic) ||
            (service_ != server->ip.characteristicWriteRequestContext.service) ||
            (accessory_ != server->ip.characteristicWriteRequestContext.accessory)) {
            HAPAssert(session->numEventNotifications <= session->maxEventNotifications);
            size_t j = 0;
            while ((j < session->numEventNotifications) &&
                   ((((HAPIPEventNotification*) &session->eventNotifications[j])->aid != aid) ||
                    (((HAPIPEventNotification*) &session->eventNotifications[j])->iid != iid))) {
                j++;
            }
            HAPAssert(
                    (j == session->numEventNotifications) ||
                    ((j < session->numEventNotifications) &&
                     (((HAPIPEventNotification*) &session->eventNotifications[j])->aid == aid) &&
                     (((HAPIPEventNotification*) &session->eventNotifications[j])->iid == iid)));
            if ((j < session->numEventNotifications) &&
                !((HAPIPEventNotification*) &session->eventNotifications[j])->flag) {
                ((HAPIPEventNotification*) &session->eventNotifications[j])->flag = true;
                session->numEventNotificationFlags++;
                events_raised++;
            }
        }
    }

    if (events_raised) {
        if (server->ip.eventNotificationTimer) {
            HAPPlatformTimerDeregister(server->ip.eventNotificationTimer);
            server->ip.eventNotificationTimer = 0;
        }
        err = HAPPlatformTimerRegister(&server->ip.eventNotificationTimer, 0, handle_event_notification_timer, server_);
        if (err) {
            HAPLog(&logObject, "Not enough resources to schedule event notification timer!");
            HAPFatalError();
        }
        HAPAssert(server->ip.eventNotificationTimer);
    }

    return kHAPError_None;
}

HAP_RESULT_USE_CHECK
static HAPError engine_raise_event(
        HAPAccessoryServerRef* server,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory) {
    HAPPrecondition(server);
    HAPPrecondition(characteristic);
    HAPPrecondition(service);
    HAPPrecondition(accessory);

    return engine_raise_event_on_session_(server, characteristic, service, accessory, /* session: */ NULL);
}

HAP_RESULT_USE_CHECK
static HAPError engine_raise_event_on_session(
        HAPAccessoryServerRef* server,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory,
        const HAPSessionRef* session) {
    HAPPrecondition(server);
    HAPPrecondition(characteristic);
    HAPPrecondition(service);
    HAPPrecondition(accessory);
    HAPPrecondition(session);

    return engine_raise_event_on_session_(server, characteristic, service, accessory, session);
}

static HAP_RESULT_USE_CHECK
HAPError finsh_put_characteristics(
        HAPAccessoryServer* server,
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContext* context) {
    HAPPrecondition(server);
    HAPPrecondition(session);
    HAPPrecondition(context->status != kHAPIPAccessoryServerStatusCode_InPorgress);

    session->inProgress.numContexts--;
    if (session->inProgress.mutliStatus == false &&
        (context->status != kHAPIPAccessoryServerStatusCode_Success || context->write.response)) {
        session->inProgress.mutliStatus = true;
    }
    if (session->inProgress.numContexts != 0) {
        return kHAPError_None;
    }

    session->inProgress.state = kHAPIPSessionInProgressState_None;
    if (session->inProgress.mutliStatus) {
        write_characteristic_write_response(
                session,
                session->contexts,
                session->numContexts);
    } else {
        write_msg(&session->outboundBuffer, kHAPIPAccessoryServerResponse_NoContent);
    }
    session->inProgress.mutliStatus = false;
    output(session);
    if (session->state == kHAPIPSessionState_Writing) {
        HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = false, .hasSpaceAvailable = true };
        HAPPlatformTCPStreamUpdateInterests(
                HAPNonnull(server->platform.ip.tcpStreamManager),
                session->tcpStream,
                interests,
                HandleTCPStreamEvent,
                session);
    }

    return kHAPError_None;
}

static HAP_RESULT_USE_CHECK
HAPError finsh_get_characteristics(
        HAPAccessoryServer* server,
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContext* context) {
    HAPPrecondition(server);
    HAPPrecondition(session);
    HAPPrecondition(context->status != kHAPIPAccessoryServerStatusCode_InPorgress);

    session->inProgress.numContexts--;
    if (session->inProgress.mutliStatus == false &&
        context->status != kHAPIPAccessoryServerStatusCode_Success) {
        session->inProgress.mutliStatus = true;
    }
    if (session->inProgress.numContexts != 0) {
        return kHAPError_None;
    }

    session->inProgress.state = kHAPIPSessionInProgressState_None;
    write_characteristic_read_response(
            session,
            session->contexts,
            session->numContexts,
            &session->inProgress.parameters,
            session->inProgress.mutliStatus);
    session->inProgress.mutliStatus = false;
    output(session);

    if (session->state == kHAPIPSessionState_Writing) {
        HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = false, .hasSpaceAvailable = true };
        HAPPlatformTCPStreamUpdateInterests(
                HAPNonnull(server->platform.ip.tcpStreamManager),
                session->tcpStream,
                interests,
                HandleTCPStreamEvent,
                session);
    }

    return kHAPError_None;
}

static HAP_RESULT_USE_CHECK
HAPError finsh_get_accessories(
        HAPAccessoryServer* server,
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContext* context) {
    HAPPrecondition(server);
    HAPPrecondition(session);
    HAPPrecondition(context->status != kHAPIPAccessoryServerStatusCode_InPorgress);

    session->inProgress.numContexts--;
    HAPAssert(session->inProgress.numContexts == 0);
    handle_accessory_serialization(session);
    if (session->state == kHAPIPSessionState_Writing) {
        HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = false, .hasSpaceAvailable = true };
        HAPPlatformTCPStreamUpdateInterests(
                HAPNonnull(server->platform.ip.tcpStreamManager),
                session->tcpStream,
                interests,
                HandleTCPStreamEvent,
                session);
    }
    return kHAPError_None;
}

static HAP_RESULT_USE_CHECK
HAPError finsh_event_notifications(
        HAPAccessoryServer* server,
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContext* context) {
    HAPPrecondition(server);
    HAPPrecondition(session);
    HAPPrecondition(context->status != kHAPIPAccessoryServerStatusCode_InPorgress);

    session->inProgress.numContexts--;
    if (session->inProgress.numContexts != 0) {
        return kHAPError_None;
    }

    HAPAssert(session->inProgress.timer);
    HAPPlatformTimerDeregister(session->inProgress.timer);
    session->inProgress.timer = 0;

    session->inProgress.state = kHAPIPSessionInProgressState_None;
    finsh_write_event_notifications(session, session->contexts, session->numContexts);
    if (session->state == kHAPIPSessionState_Writing) {
        HAPPlatformTCPStreamEvent interests = { .hasBytesAvailable = false, .hasSpaceAvailable = true };
        HAPPlatformTCPStreamUpdateInterests(
                HAPNonnull(server->platform.ip.tcpStreamManager),
                session->tcpStream,
                interests,
                HandleTCPStreamEvent,
                session);
    }
    return kHAPError_None;
}

static HAP_RESULT_USE_CHECK 
HAPError response_write_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPCharacteristic* characteristic,
        HAPError result) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state != kHAPIPSessionInProgressState_PutCharacteristics ||
        session->inProgress.numContexts == 0) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertWriteErrorToStatusCode(result);
    HAPIPCharacteristicFinshWriteRequest(
            (HAPIPSessionDescriptorRef*) session,
            characteristic,
            service,
            accessory,
            (HAPIPCharacteristicContextRef*) context,
            &session->scratchBuffer);
    if (context->status == kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_None;
    }

    return finsh_put_characteristics(server, session, context);
}

static HAP_RESULT_USE_CHECK
HAPError finsh_read_request(
        HAPAccessoryServer* server,
        HAPIPSessionDescriptor* session,
        HAPIPCharacteristicContext* context) {
    switch (session->inProgress.state) {
    case kHAPIPSessionInProgressState_GetAccessories:
        return finsh_get_accessories(server, session, context);
    case kHAPIPSessionInProgressState_PutCharacteristics:
        return finsh_put_characteristics(server, session, context);
    case kHAPIPSessionInProgressState_GetCharacteristics:
        return finsh_get_characteristics(server, session, context);
    case kHAPIPSessionInProgressState_EventNotifications:
        return finsh_event_notifications(server, session, context);
    default:
        HAPAssertionFailure();
    }

    return kHAPError_Unknown;
}

static HAP_RESULT_USE_CHECK
HAPError response_data_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPDataCharacteristic* characteristic,
        HAPError result,
        const void* valueBytes,
        size_t numValueBytes) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);
    if (result == kHAPError_None) {
        HAPPrecondition(valueBytes);
    }

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state == kHAPIPSessionInProgressState_None) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertReadErrorToStatusCode(result);
    if (context->status == kHAPIPAccessoryServerStatusCode_Success) {
        HAPIPCharacteristicContextSetDataValue(
                (HAPIPCharacteristicContextRef*) context, &session->scratchBuffer, valueBytes, numValueBytes);
    }

    return finsh_read_request(server, session, context);
}

static HAP_RESULT_USE_CHECK
HAPError response_bool_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPBoolCharacteristic* characteristic,
        HAPError result,
        bool value) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state == kHAPIPSessionInProgressState_None) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertReadErrorToStatusCode(result);
    if (context->status == kHAPIPAccessoryServerStatusCode_Success) {
        HAPIPCharacteristicContextSetUIntValue(
                (HAPIPCharacteristicContextRef*) context, value ? 1 : 0);
    }

    return finsh_read_request(server, session, context);
}

static HAP_RESULT_USE_CHECK
HAPError response_uint_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPCharacteristic* characteristic,
        HAPError result,
        uint64_t value) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state == kHAPIPSessionInProgressState_None) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertReadErrorToStatusCode(result);
    if (context->status == kHAPIPAccessoryServerStatusCode_Success) {
        HAPIPCharacteristicContextSetUIntValue(
                (HAPIPCharacteristicContextRef*) context, value);
    }

    return finsh_read_request(server, session, context);
}

static HAP_RESULT_USE_CHECK
HAPError response_uint8_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt8Characteristic* characteristic,
        HAPError result,
        uint8_t value) {
    return response_uint_read_request(_server, _session, accessory, service, characteristic, result, value);
}

static HAP_RESULT_USE_CHECK
HAPError response_uint16_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt16Characteristic* characteristic,
        HAPError result,
        uint16_t value) {
    return response_uint_read_request(_server, _session, accessory, service, characteristic, result, value);
}

static HAP_RESULT_USE_CHECK
HAPError response_uint32_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt32Characteristic* characteristic,
        HAPError result,
        uint32_t value) {
    return response_uint_read_request(_server, _session, accessory, service, characteristic, result, value);
}

static HAP_RESULT_USE_CHECK
HAPError response_uint64_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPUInt64Characteristic* characteristic,
        HAPError result,
        uint64_t value) {
    return response_uint_read_request(_server, _session, accessory, service, characteristic, result, value);
}

static HAP_RESULT_USE_CHECK
HAPError response_int_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPIntCharacteristic* characteristic,
        HAPError result,
        int32_t value) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state == kHAPIPSessionInProgressState_None) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertReadErrorToStatusCode(result);
    if (context->status == kHAPIPAccessoryServerStatusCode_Success) {
        HAPIPCharacteristicContextSetIntValue(
                (HAPIPCharacteristicContextRef*) context, value);
    }

    return finsh_read_request(server, session, context);
}

static HAP_RESULT_USE_CHECK
HAPError response_float_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPFloatCharacteristic* characteristic,
        HAPError result,
        float value) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state == kHAPIPSessionInProgressState_None) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertReadErrorToStatusCode(result);
    if (context->status == kHAPIPAccessoryServerStatusCode_Success) {
        HAPIPCharacteristicContextSetFloatValue(
                (HAPIPCharacteristicContextRef*) context, value);
    }

    return finsh_read_request(server, session, context);
}

static HAP_RESULT_USE_CHECK
HAPError response_string_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPStringCharacteristic* characteristic,
        HAPError result,
        const char* value) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);
    if (result == kHAPError_None) {
        HAPPrecondition(value);
    }

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state == kHAPIPSessionInProgressState_None) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertReadErrorToStatusCode(result);
    if (context->status == kHAPIPAccessoryServerStatusCode_Success) {
        HAPIPCharacteristicContextSetStringValue(
                (HAPIPCharacteristicContextRef*) context, &session->scratchBuffer, value);
    }

    return finsh_read_request(server, session, context);
}

static HAP_RESULT_USE_CHECK
HAPError response_tlv8_read_request(
        HAPAccessoryServerRef* _server,
        HAPSessionRef* _session,
        const HAPAccessory* accessory,
        const HAPService* service,
        const HAPTLV8Characteristic* characteristic,
        HAPError result,
        HAPTLVWriterRef* writer) {
    HAPPrecondition(_server);
    HAPPrecondition(_session);
    HAPPrecondition(accessory);
    HAPPrecondition(service);
    HAPPrecondition(characteristic);
    HAPPrecondition(result != kHAPError_InProgress);
    if (result == kHAPError_None) {
        HAPPrecondition(writer);
    }

    HAPAccessoryServer* server = (HAPAccessoryServer*) _server;
    HAPIPSessionDescriptor* session = get_session_desc_by_session_ref(server, _session);
    if (session == NULL || !session->securitySession.isOpen ||
        session->inProgress.state == kHAPIPSessionInProgressState_None) {
        return kHAPError_InvalidState;
    }

    HAPIPCharacteristicContext* context = get_ctx_by_iid(
            accessory->aid,
            ((HAPBaseCharacteristic* ) characteristic)->iid,
            session->contexts,
            session->numContexts);
    if (context == NULL || context->status != kHAPIPAccessoryServerStatusCode_InPorgress) {
        return kHAPError_InvalidState;
    }

    context->status = HAPIPCharacteristicConvertReadErrorToStatusCode(result);
    if (context->status == kHAPIPAccessoryServerStatusCode_Success) {
        HAPIPCharacteristicContextSetTLV8Value(
                (HAPIPCharacteristicContextRef*) context, &session->scratchBuffer, writer);
    }

    return finsh_read_request(server, session, context);
}

static void Create(HAPAccessoryServerRef* server_, const HAPAccessoryServerOptions* options) {
    HAPPrecondition(server_);
    HAPAccessoryServer* server = (HAPAccessoryServer*) server_;

    HAPPrecondition(server->platform.ip.tcpStreamManager);
    HAPPrecondition(server->platform.ip.serviceDiscovery);

    HAP_DIAGNOSTIC_PUSH
    HAP_DIAGNOSTIC_IGNORED_CLANG("-Wdeprecated-declarations")
    HAP_DIAGNOSTIC_IGNORED_GCC("-Wdeprecated-declarations")
    HAP_DIAGNOSTIC_IGNORED_ARMCC(2570)
    HAP_DIAGNOSTIC_IGNORED_ICCARM(Pe1444)

    HAP_DIAGNOSTIC_RESTORE_ICCARM(Pe1444)
    HAP_DIAGNOSTIC_POP

    // Initialize IP storage.
    HAPPrecondition(options->ip.accessoryServerStorage);
    HAPIPAccessoryServerStorage* storage = options->ip.accessoryServerStorage;
    HAPPrecondition(storage->sessions);
    HAPPrecondition(storage->numSessions);
    for (size_t i = 0; i < storage->numSessions; i++) {
        HAPIPSessionReset(&storage->sessions[i]);
    }
    server->ip.storage = options->ip.accessoryServerStorage;
}

static void PrepareStart(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
}

static void PrepareStop(HAPAccessoryServerRef* server_) {
    HAPPrecondition(server_);
}

static void HAPSessionInvalidateDependentIPState(HAPAccessoryServerRef* server_, HAPSessionRef* session) {
    HAPPrecondition(server_);
    HAPPrecondition(session);
}

const HAPIPAccessoryServerTransport kHAPAccessoryServerTransport_IP = {
    .create = Create,
    .prepareStart = PrepareStart,
    .prepareStop = PrepareStop,
    .session = { .invalidateDependentIPState = HAPSessionInvalidateDependentIPState },
    .serverEngine = {
        .init = engine_init,
        .deinit = engine_deinit,
        .getState = engine_get_state,
        .start = engine_start,
        .stop = engine_stop,
        .raiseEvent = engine_raise_event,
        .raiseEventOnSession = engine_raise_event_on_session,
        .responseWriteRequest = response_write_request,
        .responseDataReadRequest = response_data_read_request,
        .responseBoolReadRequest = response_bool_read_request,
        .responseUInt8ReadRequest = response_uint8_read_request,
        .responseUInt16ReadRequest = response_uint16_read_request,
        .responseUInt32ReadRequest = response_uint32_read_request,
        .responseUInt64ReadRequest = response_uint64_read_request,
        .responseIntReadRequest = response_int_read_request,
        .responseFloatReadRequest = response_float_read_request,
        .responseStringReadRequest = response_string_read_request,
        .responseTLV8ReadRequest = response_tlv8_read_request,
    }
};

HAP_RESULT_USE_CHECK
size_t HAPAccessoryServerGetIPSessionIndex(const HAPAccessoryServerRef* server_, const HAPSessionRef* session) {
    HAPPrecondition(server_);
    const HAPAccessoryServer* server = (const HAPAccessoryServer*) server_;
    HAPPrecondition(session);

    const HAPIPAccessoryServerStorage* storage = HAPNonnull(server->ip.storage);

    for (size_t i = 0; i < storage->numSessions; i++) {
        HAPIPSessionDescriptor* t = (HAPIPSessionDescriptor*) &storage->sessions[i].descriptor;
        if (!t->server) {
            continue;
        }
        if (&t->securitySession.session == session) {
            return i;
        }
    }
    HAPFatalError();
}

HAP_RESULT_USE_CHECK
bool HAPIPSessionAreEventNotificationsEnabled(
        HAPIPSessionDescriptorRef* session_,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory) {
    HAPPrecondition(session_);
    HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) session_;
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(characteristic);
    HAPPrecondition(service);
    HAPPrecondition(accessory);

    uint64_t aid = accessory->aid;
    uint64_t iid = ((const HAPBaseCharacteristic*) characteristic)->iid;

    size_t i = 0;
    while ((i < session->numEventNotifications) &&
           ((((HAPIPEventNotification*) &session->eventNotifications[i])->aid != aid) ||
            (((HAPIPEventNotification*) &session->eventNotifications[i])->iid != iid))) {
        i++;
    }
    HAPAssert(
            (i == session->numEventNotifications) ||
            ((i < session->numEventNotifications) &&
             (((HAPIPEventNotification*) &session->eventNotifications[i])->aid == aid) &&
             (((HAPIPEventNotification*) &session->eventNotifications[i])->iid == iid)));

    return i < session->numEventNotifications;
}

void HAPIPSessionHandleReadRequest(
        HAPIPSessionDescriptorRef* session_,
        HAPIPSessionContext sessionContext,
        const HAPCharacteristic* characteristic,
        const HAPService* service,
        const HAPAccessory* accessory,
        HAPIPCharacteristicContextRef* _readResult,
        HAPIPByteBuffer* dataBuffer) {
    HAPPrecondition(session_);
    HAPIPSessionDescriptor* session = (HAPIPSessionDescriptor*) session_;
    HAPPrecondition(session->server);
    HAPPrecondition(session->securitySession.isOpen);
    HAPPrecondition(session->securitySession.isSecured || kHAPIPAccessoryServer_SessionSecurityDisabled);
    HAPPrecondition(!HAPSessionIsTransient(&session->securitySession.session));
    HAPPrecondition(_readResult);
    HAPIPCharacteristicContext* readResult = (HAPIPCharacteristicContext*) _readResult;
    HAPPrecondition(dataBuffer);

    const HAPBaseCharacteristic* baseCharacteristic = (const HAPBaseCharacteristic*) characteristic;

    readResult->aid = accessory->aid;
    readResult->iid = baseCharacteristic->iid;

    if (!HAPCharacteristicReadRequiresAdminPermissions(baseCharacteristic) ||
        HAPSessionControllerIsAdmin(&session->securitySession.session)) {
        if (baseCharacteristic->properties.readable) {
            if ((sessionContext != kHAPIPSessionContext_EventNotification) &&
                HAPUUIDAreEqual(
                        baseCharacteristic->characteristicType, &kHAPCharacteristicType_ProgrammableSwitchEvent)) {
                // A read of this characteristic must always return a null value for IP accessories.
                // See HomeKit Accessory Protocol Specification R14
                // Section 9.75 Programmable Switch Event
                readResult->status = kHAPIPAccessoryServerStatusCode_Success;
                readResult->value.unsignedIntValue = 0;
            } else if (
                    (sessionContext == kHAPIPSessionContext_GetAccessories) &&
                    baseCharacteristic->properties.ip.controlPoint) {
                readResult->status = kHAPIPAccessoryServerStatusCode_UnableToPerformOperation;
            } else {
                HAPIPCharacteristicHandleReadRequest(
                        session_,
                        characteristic,
                        service,
                        accessory,
                        _readResult,
                        dataBuffer);
            }
        } else {
            readResult->status = kHAPIPAccessoryServerStatusCode_ReadFromWriteOnlyCharacteristic;
        }
    } else {
        readResult->status = kHAPIPAccessoryServerStatusCode_InsufficientPrivileges;
    }
}

#endif
