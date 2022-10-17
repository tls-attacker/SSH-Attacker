/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection;

import de.rub.nds.sshattacker.core.constants.ChannelType;
import jakarta.xml.bind.annotation.XmlAccessType;
import jakarta.xml.bind.annotation.XmlAccessorType;
import jakarta.xml.bind.annotation.XmlRootElement;
import java.io.Serializable;

@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
public class ChannelDefaults implements Serializable {

    private ChannelType channelType;
    private int localChannelId;
    private int localWindowSize;
    private int localPacketSize;
    private int remoteChannelId;
    private int remoteWindowSize;
    private int remotePacketSize;

    public ChannelDefaults() {}

    public ChannelDefaults(
            ChannelType channelType,
            int localChannelId,
            int localWindowSize,
            int localPacketSize,
            int remoteChannelId,
            int remoteWindowSize,
            int remotePacketSize) {
        this.channelType = channelType;
        this.localChannelId = localChannelId;
        this.localWindowSize = localWindowSize;
        this.localPacketSize = localPacketSize;
        this.remoteChannelId = remoteChannelId;
        this.remoteWindowSize = remoteWindowSize;
        this.remotePacketSize = remotePacketSize;
    }

    public ChannelType getChannelType() {
        return channelType;
    }

    public int getLocalChannelId() {
        return localChannelId;
    }

    public int getLocalPacketSize() {
        return localPacketSize;
    }

    public int getLocalWindowSize() {
        return localWindowSize;
    }

    public int getRemoteChannelId() {
        return remoteChannelId;
    }

    public int getRemotePacketSize() {
        return remotePacketSize;
    }

    public int getRemoteWindowSize() {
        return remoteWindowSize;
    }

    public Channel newChannelFromDefaults() {
        return new Channel(
                channelType,
                localChannelId,
                localWindowSize,
                localPacketSize,
                remoteChannelId,
                remoteWindowSize,
                remotePacketSize,
                false);
    }
}
