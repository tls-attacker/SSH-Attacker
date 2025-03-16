/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bool.ModifiableBoolean;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.ChannelDataType;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelRequestMessage;
import java.io.Serializable;
import java.util.LinkedList;
import java.util.List;

public class Channel implements Serializable {

    private ChannelType channelType;
    private ChannelDataType expectedDataType;
    private ModifiableInteger localChannelId;
    private ModifiableInteger localWindowSize;
    private ModifiableInteger localPacketSize;

    private ModifiableInteger remoteChannelId;
    private ModifiableInteger remoteWindowSize;
    private ModifiableInteger remotePacketSize;

    private ModifiableBoolean open;
    private ModifiableBoolean closeMessageReceived;
    private ModifiableBoolean closeMessageSent;

    private final List<ChannelRequestMessage<?>> receivedRequestsThatWantReply = new LinkedList<>();
    private final List<ChannelRequestMessage<?>> sentRequestsThatWantReply = new LinkedList<>();

    public Channel() {
        super();
    }

    public Channel(
            ChannelType channelType,
            Integer localChannelId,
            Integer localWindowSize,
            Integer localPacketSize,
            boolean open) {
        super();
        this.channelType = channelType;
        expectedDataType = ChannelDataType.UNSET;
        setLocalChannelId(localChannelId);
        setLocalWindowSize(localWindowSize);
        setLocalPacketSize(localPacketSize);
        setCloseMessageSent(false);
        setCloseMessageReceived(false);
        setOpen(open);
    }

    public Channel(
            ChannelType channelType,
            ModifiableInteger localChannelId,
            ModifiableInteger localWindowSize,
            ModifiableInteger localPacketSize,
            Boolean open) {
        super();
        this.channelType = channelType;
        expectedDataType = ChannelDataType.UNSET;
        this.localChannelId = localChannelId;
        this.localWindowSize = localWindowSize;
        this.localPacketSize = localPacketSize;
        setCloseMessageSent(false);
        setCloseMessageReceived(false);
        setOpen(open);
    }

    public Channel(
            ChannelType channelType,
            Integer localChannelId,
            Integer localWindowSize,
            Integer localPacketSize,
            Integer remoteChannelId,
            Integer remoteWindowSize,
            Integer remotePacketSize,
            Boolean open) {
        super();
        this.channelType = channelType;
        expectedDataType = ChannelDataType.UNSET;
        setLocalChannelId(localChannelId);
        setLocalWindowSize(localWindowSize);
        setLocalPacketSize(localPacketSize);
        setRemoteChannelId(remoteChannelId);
        setRemoteWindowSize(remoteWindowSize);
        setRemotePacketSize(remotePacketSize);
        setCloseMessageSent(false);
        setCloseMessageReceived(false);
        setOpen(open);
    }

    public Channel(
            ChannelType channelType,
            ChannelDataType expectedDataType,
            Integer localChannelId,
            Integer localWindowSize,
            Integer localPacketSize,
            Integer remoteChannelId,
            Integer remoteWindowSize,
            Integer remotePacketSize,
            Boolean open) {
        super();
        this.channelType = channelType;
        this.expectedDataType = expectedDataType;
        setLocalChannelId(localChannelId);
        setLocalWindowSize(localWindowSize);
        setLocalPacketSize(localPacketSize);
        setRemoteChannelId(remoteChannelId);
        setRemoteWindowSize(remoteWindowSize);
        setRemotePacketSize(remotePacketSize);
        setCloseMessageSent(false);
        setCloseMessageReceived(false);
        setOpen(open);
    }

    public ChannelType getChannelType() {
        return channelType;
    }

    public void setChannelType(ChannelType channelType) {
        this.channelType = channelType;
    }

    public ChannelDataType getExpectedDataType() {
        return expectedDataType;
    }

    public void setExpectedDataType(ChannelDataType expectedDataType) {
        this.expectedDataType = expectedDataType;
    }

    public ModifiableInteger getLocalPacketSize() {
        return localPacketSize;
    }

    public void setLocalPacketSize(ModifiableInteger localPacketSize) {
        this.localPacketSize = localPacketSize;
    }

    public void setLocalPacketSize(Integer localPacketSize) {
        this.localPacketSize =
                ModifiableVariableFactory.safelySetValue(this.localPacketSize, localPacketSize);
    }

    @SuppressWarnings("NonBooleanMethodNameMayNotStartWithQuestion")
    public ModifiableBoolean isOpen() {
        return open;
    }

    public void setOpen(ModifiableBoolean open) {
        this.open = open;
    }

    public void setOpen(Boolean open) {
        this.open = ModifiableVariableFactory.safelySetValue(this.open, open);
    }

    public ModifiableBoolean getCloseMessageReceived() {
        return closeMessageReceived;
    }

    public void setCloseMessageReceived(ModifiableBoolean closeMessageReceived) {
        this.closeMessageReceived = closeMessageReceived;
        if (closeMessageSent.getValue() && this.closeMessageReceived.getValue()) {
            setOpen(false);
        }
    }

    public void setCloseMessageReceived(boolean closeMessageReceived) {
        this.closeMessageReceived =
                ModifiableVariableFactory.safelySetValue(
                        this.closeMessageReceived, closeMessageReceived);
        if (closeMessageSent.getValue() && this.closeMessageReceived.getValue()) {
            setOpen(false);
        }
    }

    public ModifiableBoolean getCloseMessageSent() {
        return closeMessageSent;
    }

    public void setCloseMessageSent(ModifiableBoolean closeMessageSent) {
        this.closeMessageSent = closeMessageSent;
        if (this.closeMessageSent.getValue() && closeMessageReceived.getValue()) {
            setOpen(false);
        }
    }

    public void setCloseMessageSent(boolean closeMessageSent) {
        this.closeMessageSent =
                ModifiableVariableFactory.safelySetValue(this.closeMessageSent, closeMessageSent);
        if (this.closeMessageSent.getValue() && closeMessageReceived.getValue()) {
            setOpen(false);
        }
    }

    public ModifiableInteger getLocalWindowSize() {
        return localWindowSize;
    }

    public void setLocalWindowSize(ModifiableInteger localWindowSize) {
        this.localWindowSize = localWindowSize;
    }

    public void setLocalWindowSize(Integer localWindowSize) {
        this.localWindowSize =
                ModifiableVariableFactory.safelySetValue(this.localWindowSize, localWindowSize);
    }

    public ModifiableInteger getLocalChannelId() {
        return localChannelId;
    }

    public void setLocalChannelId(ModifiableInteger localChannelId) {
        this.localChannelId = localChannelId;
    }

    public void setLocalChannelId(Integer localChannelId) {
        this.localChannelId =
                ModifiableVariableFactory.safelySetValue(this.localChannelId, localChannelId);
    }

    public ModifiableInteger getRemoteChannelId() {
        return remoteChannelId;
    }

    public void setRemoteChannelId(ModifiableInteger remoteChannelId) {
        this.remoteChannelId = remoteChannelId;
    }

    public void setRemoteChannelId(Integer remoteChannelId) {
        this.remoteChannelId =
                ModifiableVariableFactory.safelySetValue(this.remoteChannelId, remoteChannelId);
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

    public void addReceivedRequestThatWantsReply(ChannelRequestMessage<?> message) {
        receivedRequestsThatWantReply.add(message);
    }

    public void addSentRequestsThatWantsReply(ChannelRequestMessage<?> message) {
        sentRequestsThatWantReply.add(message);
    }

    public ChannelRequestMessage<?> removeFirstReceivedRequestThatWantReply() {
        if (!receivedRequestsThatWantReply.isEmpty()) {
            return receivedRequestsThatWantReply.removeFirst();
        }
        return null;
    }

    public ChannelRequestMessage<?> removeFirstSentRequestThatWantReply() {
        if (!sentRequestsThatWantReply.isEmpty()) {
            return sentRequestsThatWantReply.removeFirst();
        }
        return null;
    }

    @Override
    public String toString() {
        return "\n"
                + "Channel{"
                + "\n"
                + " channelType: "
                + channelType.toString()
                + "\n"
                + " channelDataType: "
                + expectedDataType.toString()
                + "\n"
                + " localChannelId: "
                + localChannelId.getValue()
                + "\n"
                + " localWindowSize: "
                + localWindowSize.getValue()
                + "\n"
                + " localPacketSize: "
                + localPacketSize.getValue()
                + "\n"
                + " remoteChannelId: "
                + remoteChannelId.getValue()
                + "\n"
                + " remoteWindowSize: "
                + remoteWindowSize.getValue()
                + "\n"
                + " remotePacketSize: "
                + remotePacketSize.getValue()
                + "\n"
                + " open:"
                + open.getValue()
                + "\n"
                + " closeMessageSent: "
                + closeMessageSent.getValue()
                + "\n"
                + " closeMessageReceived: "
                + closeMessageReceived.getValue()
                + "\n"
                + '}';
    }
}
