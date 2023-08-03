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
    SSH_CMSG_REQUEST_COMPRESSION((byte) 37);

    /*
     * Sources:
     *  - https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-1
     */
    // [ RFC 4253 ]
    /*VERSION_EXCHANGE_MESSAGE((byte) 200),
    ASCII_MESSAGE((byte) 201),
    SSH_MSG_DISCONNECT((byte) 1),
    SSH_MSG_IGNORE((byte) 2),
    SSH_MSG_UNIMPLEMENTED((byte) 3),
    SSH_MSG_DEBUG((byte) 4),
    SSH_MSG_SERVICE_REQUEST((byte) 5),
    SSH_MSG_SERVICE_ACCEPT((byte) 6),
    // [ RFC 8308 ]
    SSH_MSG_EXT_INFO((byte) 7),
    SSH_MSG_NEWCOMPRESS((byte) 8),
    // 9 - 19 unassigned (transport layer generic)
    SSH_MSG_KEXINIT((byte) 20),
    SSH_MSG_NEWKEYS((byte) 21),
    // 22 - 29 unassigned (algorithm negotiation)
    // 30 - 49 reserved (key exchange method specific)
    // [ RFC 4419 ]
    SSH_MSG_KEX_DH_GEX_REQUEST_OLD((byte) 30, KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE),
    SSH_MSG_KEX_DH_GEX_REQUEST((byte) 34, KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE),
    SSH_MSG_KEX_DH_GEX_GROUP((byte) 31, KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE),
    SSH_MSG_KEX_DH_GEX_INIT((byte) 32, KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE),
    SSH_MSG_KEX_DH_GEX_REPLY((byte) 33, KeyExchangeFlowType.DIFFIE_HELLMAN_GROUP_EXCHANGE),
    // [ RFC 4253 ]
    SSH_MSG_KEXDH_INIT((byte) 30, KeyExchangeFlowType.DIFFIE_HELLMAN),
    SSH_MSG_KEXDH_REPLY((byte) 31, KeyExchangeFlowType.DIFFIE_HELLMAN),
    // [ https://datatracker.ietf.org/doc/html/draft-kampanakis-curdle-pq-ssh-00 ]
    SSH_MSG_HBR_INIT((byte) 30, KeyExchangeFlowType.HYBRID),
    SSH_MSG_HBR_REPLY((byte) 31, KeyExchangeFlowType.HYBRID),
    // [ RFC 5656 ]
    SSH_MSG_KEX_ECDH_INIT((byte) 30, KeyExchangeFlowType.ECDH),
    SSH_MSG_KEX_ECDH_REPLY((byte) 31, KeyExchangeFlowType.ECDH),
    SSH_MSG_ECMQV_INIT((byte) 30, KeyExchangeFlowType.ECMQV),
    SSH_MSG_ECMQV_REPLY((byte) 31, KeyExchangeFlowType.ECMQV),
    // [ RFC 4432 ]
    SSH_MSG_KEXRSA_PUBKEY((byte) 30, KeyExchangeFlowType.RSA),
    SSH_MSG_KEXRSA_SECRET((byte) 31, KeyExchangeFlowType.RSA),
    SSH_MSG_KEXRSA_DONE((byte) 32, KeyExchangeFlowType.RSA),
    // [ RFC 4462 ]
    // TODO: Add specificTo on GSS messages
    SSH_MSG_KEXGSS_INIT((byte) 30),
    SSH_MSG_KEXGSS_CONTINUE((byte) 31),
    SSH_MSG_KEXGSS_COMPLETE((byte) 32),
    SSH_MSG_KEXGSS_HOSTKEY((byte) 33),
    SSH_MSG_KEXGSS_ERROR((byte) 34),
    SSH_MSG_KEXGSS_GROUPREQ((byte) 40),
    SSH_MSG_KEXGSS_GROUP((byte) 41),
    // [ RFC 4252 ]
    SSH_MSG_USERAUTH_REQUEST((byte) 50),
    SSH_MSG_USERAUTH_FAILURE((byte) 51),
    SSH_MSG_USERAUTH_SUCCESS((byte) 52),
    SSH_MSG_USERAUTH_BANNER((byte) 53),
    // 54 - 59 unassigned (user authentication generic)
    // 60 - 79 reserved (user authentication method specific)
    // [ RFC 4252 ]
    SSH_MSG_USERAUTH_PK_OK((byte) 60, AuthenticationMethod.PUBLICKEY),
    SSH_MSG_USERAUTH_PASSWD_CHANGEREQ((byte) 60, AuthenticationMethod.PASSWORD),
    // [ RFC 4256 ]
    SSH_MSG_USERAUTH_INFO_REQUEST((byte) 60, AuthenticationMethod.KEYBOARD_INTERACTIVE),
    SSH_MSG_USERAUTH_INFO_RESPONSE((byte) 61, AuthenticationMethod.KEYBOARD_INTERACTIVE),
    // [ RFC 4462 ]
    SSH_MSG_USERAUTH_GSSAPI_RESPONSE(
            (byte) 60,
            new AuthenticationMethod[] {
                AuthenticationMethod.GSSAPI,
                AuthenticationMethod.GSSAPI_WITH_MIC,
                AuthenticationMethod.GSSAPI_KEYEX
            }),
    SSH_MSG_USERAUTH_GSSAPI_TOKEN(
            (byte) 61,
            new AuthenticationMethod[] {
                AuthenticationMethod.GSSAPI,
                AuthenticationMethod.GSSAPI_WITH_MIC,
                AuthenticationMethod.GSSAPI_KEYEX
            }),
    SSH_MSG_USERAUTH_GSSAPI_EXCHANGE_COMPLETE(
            (byte) 63,
            new AuthenticationMethod[] {
                AuthenticationMethod.GSSAPI,
                AuthenticationMethod.GSSAPI_WITH_MIC,
                AuthenticationMethod.GSSAPI_KEYEX
            }),
    SSH_MSG_USERAUTH_GSSAPI_ERROR(
            (byte) 64,
            new AuthenticationMethod[] {
                AuthenticationMethod.GSSAPI,
                AuthenticationMethod.GSSAPI_WITH_MIC,
                AuthenticationMethod.GSSAPI_KEYEX
            }),
    SSH_MSG_USERAUTH_GSSAPI_ERRTOK(
            (byte) 65,
            new AuthenticationMethod[] {
                AuthenticationMethod.GSSAPI,
                AuthenticationMethod.GSSAPI_WITH_MIC,
                AuthenticationMethod.GSSAPI_KEYEX
            }),
    SSH_MSG_USERAUTH_GSSAPI_MIC(
            (byte) 66,
            new AuthenticationMethod[] {
                AuthenticationMethod.GSSAPI,
                AuthenticationMethod.GSSAPI_WITH_MIC,
                AuthenticationMethod.GSSAPI_KEYEX
            }),
    // [ RFC 4254 ]
    SSH_MSG_GLOBAL_REQUEST((byte) 80),
    SSH_MSG_REQUEST_SUCCESS((byte) 81),
    SSH_MSG_REQUEST_FAILURE((byte) 82),
    // 83 - 89 unassigned (connection protocol generic)
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
    // 101 - 127 unassigned (channel related messages)
    // 128 - 191 reserved (for client protocols)
    // 192 - 255 reserved for private use (local extensions)
    UNKNOWN((byte) 255);*/

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
        if (id >= (byte) 30 && id <= (byte) 49) {
            KeyExchangeAlgorithm kexInContext = context.getChooser().getKeyExchangeAlgorithm();
            for (MessageIdConstantSSH1 candidate : idList) {
                if (Arrays.asList(candidate.specificTo).contains(kexInContext.getFlowType())) {
                    return candidate;
                }
            }
            throw new ParserException(
                    "Unable to parse key exchange specific message in the current context");
        }
        if (id >= (byte) 60 && id <= (byte) 79) {
            AuthenticationMethod methodInContext = context.getChooser().getAuthenticationMethod();
            if (methodInContext == null) {
                throw new ParserException(
                        "Unable to parse user authentication specific message id without selecting one first");
            }
            for (MessageIdConstantSSH1 candidate : idList) {
                if (Arrays.asList(candidate.specificTo).contains(methodInContext)) {
                    return candidate;
                }
            }
            throw new ParserException(
                    "Unable to parse user authentication specific message in the current context");
        }
        return idList.get(0);
    }
}
