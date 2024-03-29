/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

import de.rub.nds.sshattacker.core.exceptions.ParserException;
import de.rub.nds.sshattacker.core.state.Context;
import java.util.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public enum MessageIdConstantSSH1 {
    VERSION_EXCHANGE_MESSAGE_SSH1((byte) 0),
    ASCII_MESSAGE((byte) 40),
    SSH_MSG_DISCONNECT((byte) 1),
    SSH_SMSG_PUBLIC_KEY((byte) 2),
    SSH_CMSG_SESSION_KEY((byte) 3),
    SSH_CMSG_USER((byte) 4),
    SSH_CMSG_AUTH_RHOSTS((byte) 5),
    SSH_CMSG_AUTH_RSA((byte) 6),
    SSH_SMSG_AUTH_RSA_CHALLENGE((byte) 7),
    SSH_CMSG_AUTH_RSA_RESPONSE((byte) 8),
    SSH_CMSG_AUTH_PASSWORD((byte) 9),
    SSH_CMSG_REQUEST_PTY((byte) 10),
    SSH_CMSG_WINDOW_SIZE((byte) 11),
    SSH_CMSG_EXEC_SHELL((byte) 12),
    SSH_CMSG_EXEC_CMD((byte) 13),
    SSH_SMSG_SUCCESS((byte) 14),
    SSH_SMSG_FAILURE((byte) 15),
    SSH_CMSG_STDIN_DATA((byte) 16),
    SSH_SMSG_STDOUT_DATA((byte) 17),
    SSH_SMSG_STDERR_DATA((byte) 18),
    SSH_CMSG_EOF((byte) 19),
    SSH_SMSG_EXITSTATUS((byte) 20),
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION((byte) 21),
    SSH_MSG_CHANNEL_OPEN_FAILURE((byte) 22),
    SSH_MSG_CHANNEL_DATA((byte) 23),
    SSH_MSG_CHANNEL_CLOSE((byte) 24),
    SSH_MSG_CHANNEL_CLOSE_CONFIRMATION((byte) 25),
    SSH_SMSG_X11_OPEN((byte) 27),
    SSH_CMSG_PORT_FORWARD_REQUEST((byte) 28),
    SSH_MSG_PORT_OPEN((byte) 29),
    SSH_CMSG_AGENT_REQUEST_FORWARDING((byte) 30),
    SSH_SMSG_AGENT_OPEN((byte) 31),
    SSH_MSG_IGNORE((byte) 32),
    SSH_CMSG_EXIT_CONFIRMATION((byte) 33),
    SSH_CMSG_X11_REQUEST_FORWARDING((byte) 34),
    SSH_CMSG_AUTH_RHOSTS_RSA((byte) 35),
    SSH_MSG_DEBUG((byte) 36),
    SSH_CMSG_REQUEST_COMPRESSION((byte) 37),
    SSH_CMSG_MAX_PACKET_SIZE((byte) 38),
    SSH_CMSG_AUTH_TIS((byte) 39),
    SSH_SMSG_AUTH_TIS_CHALLENGE((byte) 40),
    SSH_CMSG_AUTH_TIS_RESPONSE((byte) 41),
    SSH_CMSG_AUTH_KERBEROS((byte) 42),
    SSH_SMSG_AUTH_KERBEROS_RESPONSE((byte) 43),
    SSH_CMSG_HAVE_KERBEROS_TGT((byte) 44),
    SSH_CMSG_HAVE_AFS_TOKEN((byte) 65);

    private final byte id;
    private final Enum<?>[] specificTo;

    public static final Map<Byte, List<MessageIdConstantSSH1>> map;

    private static final Logger LOGGER = LogManager.getLogger();

    static {
        Map<Byte, List<MessageIdConstantSSH1>> mutableMap = new TreeMap<>();
        for (MessageIdConstantSSH1 constant : MessageIdConstantSSH1.values()) {
            mutableMap.putIfAbsent(constant.id, new LinkedList<>());
            mutableMap.get(constant.id).add(constant);
        }
        mutableMap.replaceAll((k, v) -> Collections.unmodifiableList(mutableMap.get(k)));
        map = Collections.unmodifiableMap(mutableMap);
    }

    MessageIdConstantSSH1(byte id) {
        this.id = id;
        this.specificTo = new Enum<?>[] {};
    }

    MessageIdConstantSSH1(byte id, Enum<?>... specificTo) {
        this.id = id;
        this.specificTo = specificTo;
    }

    public byte getId() {
        return id;
    }

    public static String getNameById(byte id) {
        if (map.containsKey(id)) {
            return map.get(id).toString();
        } else {
            return String.format("0x%02X", id);
        }
    }

    public static MessageIdConstantSSH1 fromId(byte id, Context context) {
        List<MessageIdConstantSSH1> idList = map.get(id);
        if (idList == null) {
            LOGGER.warn("Unknonw Message-ID: {}", id);
            throw new ParserException("Unable to parse message with unknown id");
        }
        return idList.get(0);
    }
}
