/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import java.util.Map;
import java.util.TreeMap;

public enum DisconnectReason {
    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-3
     */
    // [ RFC 4253 ]
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT(1),
    SSH_DISCONNECT_PROTOCOL_ERROR(2),
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED(3),
    SSH_DISCONNECT_RESERVED(4),
    SSH_DISCONNECT_MAC_ERROR(5),
    SSH_DISCONNECT_COMPRESSION_ERROR(6),
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE(7),
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED(8),
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE(9),
    SSH_DISCONNECT_CONNECTION_LOST(10),
    SSH_DISCONNECT_BY_APPLICATION(11),
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS(12),
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER(13),
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE(14),
    SSH_DISCONNECT_ILLEGAL_USER_NAME(15);

    public final int id;

    public static final Map<Integer, DisconnectReason> map;

    static {
        map = new TreeMap<>();
        for (DisconnectReason constant : DisconnectReason.values()) {
            map.put(constant.id, constant);
        }
    }

    DisconnectReason(int id) {
        this.id = id;
    }

    public static String getNameByID(int id) {
        return map.get(id).toString();
    }

    public static DisconnectReason fromId(int id) {
        return map.get(id);
    }
}
