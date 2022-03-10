/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.connection;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import java.io.Serializable;
import java.util.HashMap;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Channel implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    private ChannelType channelType;
    private ModifiableInteger localChannel;
    private ModifiableInteger localWindowSize;
    private ModifiableInteger localPacketSize;

    private ModifiableInteger remoteChannel;
    private ModifiableInteger remoteWindowSize;
    private ModifiableInteger remotePacketSize;

    private ModifiableBoolean open;
    private ModifiableBoolean firstCloseMessage;

    private static HashMap<Integer, Integer> local_remote = new HashMap<>();

    public Channel(
            ChannelType channelType,
            ModifiableInteger localChannel,
            ModifiableInteger localWindowSize,
            ModifiableInteger localPacketSize,
            Boolean open) {
        this.channelType = channelType;
        this.localChannel = localChannel;
        this.localWindowSize = localWindowSize;
        this.localPacketSize = localPacketSize;
        setFirstCloseMessage(false);
        setOpen(open);
    }

    public Channel(
            ChannelType channelType,
            Integer localChannel,
            Integer localWindowSize,
            Integer localPacketSize,
            Integer remoteChannel,
            Integer remoteWindowSize,
            Integer remotePacketSize,
            Boolean open) {
        this.channelType = channelType;
        setLocalChannel(localChannel);
        setLocalWindowSize(localWindowSize);
        setlocalPacketSize(localPacketSize);
        setRemoteChannel(remoteChannel);
        setRemoteWindowSize(remoteWindowSize);
        setRemotePacketSize(remotePacketSize);
        setFirstCloseMessage(false);
        setOpen(open);
    }

    public ChannelType getChannelType() {
        return channelType;
    }

    public void setChannelType(ChannelType channelType) {
        this.channelType = channelType;
    }

    public ModifiableInteger getlocalPacketSize() {
        return localPacketSize;
    }

    public void setlocalPacketSize(ModifiableInteger localPacketSize) {
        this.localPacketSize = localPacketSize;
    }

    public void setlocalPacketSize(Integer localPacketSize) {
        this.localPacketSize =
                ModifiableVariableFactory.safelySetValue(this.localPacketSize, localPacketSize);
    }

    public ModifiableBoolean isOpen() {
        return open;
    }

    public void setOpen(ModifiableBoolean open) {
        this.open = open;
    }

    public void setOpen(Boolean open) {
        this.open = ModifiableVariableFactory.safelySetValue(this.open, open);
    }

    public ModifiableInteger getlocalWindowSize() {
        return localWindowSize;
    }

    public void setlocalWindowSize(ModifiableInteger localWindowSize) {
        this.localWindowSize = localWindowSize;
    }

    public void setLocalWindowSize(Integer localWindowSize) {
        this.localWindowSize =
                ModifiableVariableFactory.safelySetValue(this.localWindowSize, localWindowSize);
    }

    public ModifiableInteger getLocalChannel() {
        return localChannel;
    }

    public void setLocalChannel(ModifiableInteger localChannel) {
        this.localChannel = localChannel;
    }

    public void setLocalChannel(Integer localChannel) {
        this.localChannel =
                ModifiableVariableFactory.safelySetValue(this.localChannel, localChannel);
    }

    public ModifiableInteger getRemoteChannel() {
        return remoteChannel;
    }

    public void setRemoteChannel(ModifiableInteger remoteChannel) {
        this.remoteChannel = remoteChannel;
    }

    public void setRemoteChannel(Integer remoteChannel) {
        this.remoteChannel =
                ModifiableVariableFactory.safelySetValue(this.remoteChannel, remoteChannel);
    }

    public ModifiableInteger getRemotePacketSize() {
        return remotePacketSize;
    }

    public void setRemotePacketSize(ModifiableInteger remotePacketSize) {
        this.remotePacketSize = remotePacketSize;
    }

    public void setRemotePacketSize(Integer remotePacketSize) {
        this.remotePacketSize =
                ModifiableVariableFactory.safelySetValue(this.remotePacketSize, remotePacketSize);
    }

    public ModifiableInteger getRemoteWindowSize() {
        return remoteWindowSize;
    }

    public void setRemoteWindowSize(ModifiableInteger remoteWindowSize) {
        this.remoteWindowSize = remoteWindowSize;
    }

    public void setRemoteWindowSize(Integer remoteWindowSize) {
        this.remoteWindowSize =
                ModifiableVariableFactory.safelySetValue(this.remoteWindowSize, remoteWindowSize);
    }

    public ModifiableBoolean getFirstCloseMessage() {
        return firstCloseMessage;
    }

    public void setFirstCloseMessage(ModifiableBoolean firstCloseMessage) {
        this.firstCloseMessage = firstCloseMessage;
    }

    public void setFirstCloseMessage(Boolean firstCloseMessage) {
        this.firstCloseMessage =
                ModifiableVariableFactory.safelySetValue(this.firstCloseMessage, firstCloseMessage);
    }

    @Override
    public String toString() {
        return "\n"
                + "Channel{"
                + "\n"
                + " channelType:"
                + channelType.toString()
                + "\n"
                + " localChannel:"
                + localChannel.getValue()
                + "\n"
                + " localWindowSize:"
                + localWindowSize.getValue()
                + "\n"
                + " localPacketSize:"
                + localPacketSize.getValue()
                + "\n"
                + " remoteChannel:"
                + remoteChannel.getValue()
                + "\n"
                + " remoteWindowSize:"
                + remoteWindowSize.getValue()
                + "\n"
                + " remotePacketSize:"
                + remotePacketSize.getValue()
                + "\n"
                + " open:"
                + open.getValue()
                + "\n"
                + " firstCloseMessage:"
                + firstCloseMessage.getValue()
                + "\n"
                + '}';
    }

    public static HashMap<Integer, Integer> getLocal_remote() {
        return local_remote;
    }
}
