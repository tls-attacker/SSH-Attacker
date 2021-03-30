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

public enum MessageIDConstant {
    SSH_MSG_DISCONNECT((byte) 1),
    SSH_MSG_IGNORE((byte) 2),
    SSH_MSG_UNIMPLEMENTED((byte) 3),
    SSH_MSG_DEBUG((byte) 4),
    SSH_MSG_SERVICE_REQUEST((byte) 5),
    SSH_MSG_SERVICE_ACCEPT((byte) 6),
    SSH_MSG_KEXINIT((byte) 20),
    SSH_MSG_NEWKEYS((byte) 21),
    SSH_MSG_KEX_ECDH_INIT((byte) 30),
    SSH_MSG_KEX_ECDH_REPLY((byte) 31),
    // these collide with the current default of ECDH in the hashmap so they are
    // disabled
    // SSH_MSG_KEXDH_INIT((byte) 30),
    // SSH_MSG_KEXDH_REPLY((byte) 31),
    // SSH_MSG_ECMQV_INIT((byte) 30),
    // SSH_MSG_ECMQV_REPLY((byte) 31),
    SSH_MSG_USERAUTH_REQUEST((byte) 50),
    SSH_MSG_USERAUTH_FAILURE((byte) 51),
    SSH_MSG_USERAUTH_SUCCESS((byte) 52),
    SSH_MSG_USERAUTH_BANNER((byte) 53),
    SSH_MSG_GLOBAL_REQUEST((byte) 80),
    SSH_MSG_REQUEST_SUCCESS((byte) 81),
    SSH_MSG_REQUEST_FAILURE((byte) 82),
    SSH_MSG_CHANNEL_OPEN((byte) 90),
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION((byte) 91),
    SSH_MSG_CHANNEL_OPEN_FAILURE((byte) 92),
    SSH_MSG_CHANNEL_WINDOW_ADJUST((byte) 93),
    SSH_MSG_CHANNEL_DATA((byte) 94),
    SSH_MSG_CHANNEL_EXTENDED_DATA((byte) 95),
    SSH_MSG_CHANNEL_EOF((byte) 96),
    SSH_MSG_CHANNEL_CLOSE((byte) 97),
    SSH_MSG_CHANNEL_REQUEST((byte) 98),
    SSH_MSG_CHANNEL_SUCCESS((byte) 99),
    SSH_MSG_CHANNEL_FAILURE((byte) 100),
    UNKNOWN((byte) 255); // reserved by us

    public final byte id;

    public static final Map<Byte, MessageIDConstant> map;

    static {
        map = new TreeMap<>();
        for (MessageIDConstant constant : MessageIDConstant.values()) {
            map.put(constant.id, constant);
        }
    }

    MessageIDConstant(byte id) {
        this.id = id;
    }

    public static String getNameByID(byte id) {
        return map.get(id).toString();
    }

    public static MessageIDConstant fromId(byte id) {
        return map.get(id);
    }
}
