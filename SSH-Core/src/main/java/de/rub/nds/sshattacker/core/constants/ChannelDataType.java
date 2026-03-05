/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

/** Represents data types that can occur when receiving SSH_MSG_CHANNEL_DATA */
public enum ChannelDataType {

    // Only valid in channels in which no channel request has been confirmed yet
    /** Not requested data */
    UNSET,

    // Only valid in SESSION ChannelType
    /** Pseudo-terminal (pty) data stream */
    PTY,
    /** Arbitrary std-out data stream of programs, executed with exec or a shell */
    SHELL,
    /** SFTP protocol data */
    SUBSYSTEM_SFTP,
    /** Unknown subsystem data */
    SUBSYSTEM_UNKNOWN,

    // Only valid in X11 ChannelType
    /** X11 forwarding data stream */
    X11,

    // Only valid in FORWARDED_TCPIP and DIRECT_TCPIP ChannelType
    /** TCP IP data stream */
    TCP_IP,

    // Only valid in TUN_OPENSSH_COM ChannelType
    /** TCP IP data stream */
    TUN,

    //  Only valid in DIRECT_STREAMLOCAL_OPENSSH_COM and FORWARDED_STREAMLOCAL_OPENSSH_COM
    // ChannelType
    /** Unix domain socket data stream */
    UNIX_DOMAIN,

    //  Only valid in AUTH_AGENT_OPENSSH_COM ChannelType
    /** SSH Agent Protocol data */
    AUTH_AGENT,
    // Only valid if more than one channel request that changes the expected data type were
    // confirmed
    /** Unknown data stream, because multiple types are possible */
    UNKNOWN
}
