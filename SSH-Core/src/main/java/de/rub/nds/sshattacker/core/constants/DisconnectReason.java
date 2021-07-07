/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
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
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT((byte) 1),
    SSH_DISCONNECT_PROTOCOL_ERROR((byte) 2),
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED((byte) 3),
    SSH_DISCONNECT_RESERVED((byte) 4),
    SSH_DISCONNECT_MAC_ERROR((byte) 5),
    SSH_DISCONNECT_COMPRESSION_ERROR((byte) 6),
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE((byte) 7),
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED((byte) 8),
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE((byte) 9),
    SSH_DISCONNECT_CONNECTION_LOST((byte) 10),
    SSH_DISCONNECT_BY_APPLICATION((byte) 11),
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS((byte) 12),
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER((byte) 13),
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE((byte) 14),
    SSH_DISCONNECT_ILLEGAL_USER_NAME((byte) 15);

    public final byte id;

    public static final Map<Byte, DisconnectReason> map;

    static {
        map = new TreeMap<>();
        for (DisconnectReason constant : DisconnectReason.values()) {
            map.put(constant.id, constant);
        }
    }

    DisconnectReason(byte id) {
        this.id = id;
    }

    public static String getNameByID(byte id) {
        return map.get(id).toString();
    }

    public static DisconnectReason fromId(byte id) {
        return map.get(id);
    }
}
