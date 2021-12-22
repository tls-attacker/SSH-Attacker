/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenConfirmationMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenConfirmationMessage extends ChannelMessage<ChannelOpenConfirmationMessage> {

    private ModifiableInteger modSenderChannel;
    private ModifiableInteger windowSize;
    private Integer transferWindowSize;
    private ModifiableInteger packetSize;
    private Integer transferPacketSize;

    public ChannelOpenConfirmationMessage() {
        super(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    }

    public ChannelOpenConfirmationMessage(Integer senderChannel) {
        super(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, senderChannel);
    }

    public ChannelOpenConfirmationMessage(
            Integer senderChannel, Integer windowSize, Integer packetSize) {
        super(MessageIDConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION, senderChannel);
        setTransferWindowSize(windowSize);
        setTransferPacketSize(packetSize);
    }

    public ModifiableInteger getModSenderChannel() {
        return modSenderChannel;
    }

    public void setModSenderChannel(ModifiableInteger modSenderChannel) {
        this.modSenderChannel = modSenderChannel;
    }

    public void setModSenderChannel(int modSenderChannel) {
        this.modSenderChannel =
                ModifiableVariableFactory.safelySetValue(this.modSenderChannel, modSenderChannel);
    }

    public ModifiableInteger getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(ModifiableInteger windowSize) {
        this.windowSize = windowSize;
    }

    public void setWindowSize(int windowSize) {
        this.windowSize = ModifiableVariableFactory.safelySetValue(this.windowSize, windowSize);
    }

    public ModifiableInteger getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(ModifiableInteger packetSize) {
        this.packetSize = packetSize;
    }

    public void setPacketSize(int packetSize) {
        this.packetSize = ModifiableVariableFactory.safelySetValue(this.packetSize, packetSize);
    }

    public Integer getTransferPacketSize() {
        return transferPacketSize;
    }

    public void setTransferPacketSize(Integer transferPacketSize) {
        this.transferPacketSize = transferPacketSize;
    }

    public Integer getTransferWindowSize() {
        return transferWindowSize;
    }

    public void setTransferWindowSize(Integer transferWindowSize) {
        this.transferWindowSize = transferWindowSize;
    }

    @Override
    public ChannelOpenConfirmationMessageHandler getHandler(SshContext context) {
        return new ChannelOpenConfirmationMessageHandler(context, this);
    }
}
