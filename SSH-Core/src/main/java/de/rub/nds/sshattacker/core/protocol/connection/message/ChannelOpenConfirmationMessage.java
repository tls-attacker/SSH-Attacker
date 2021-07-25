/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelOpenConfirmationMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelOpenConfirmationMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelOpenConfirmationMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelOpenConfirmationMessage extends Message<ChannelOpenConfirmationMessage> {

    private ModifiableInteger recipientChannel;
    private ModifiableInteger senderChannel;
    private ModifiableInteger windowSize;
    private ModifiableInteger packetSize;

    public ModifiableInteger getRecipientChannel() {
        return recipientChannel;
    }

    public void setRecipientChannel(ModifiableInteger recipientChannel) {
        this.recipientChannel = recipientChannel;
    }

    public void setRecipientChannel(int recipientChannel) {
        this.recipientChannel = ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
    }

    public ModifiableInteger getSenderChannel() {
        return senderChannel;
    }

    public void setSenderChannel(ModifiableInteger senderChannel) {
        this.senderChannel = senderChannel;
    }

    public void setSenderChannel(Integer senderChannel) {
        this.senderChannel = ModifiableVariableFactory.safelySetValue(this.senderChannel, senderChannel);
    }

    public ModifiableInteger getWindowSize() {
        return windowSize;
    }

    public void setWindowSize(ModifiableInteger windowSize) {
        this.windowSize = windowSize;
    }

    public void setWindowSize(Integer windowSize) {
        this.windowSize = ModifiableVariableFactory.safelySetValue(this.windowSize, windowSize);
    }

    public ModifiableInteger getPacketSize() {
        return packetSize;
    }

    public void setPacketSize(ModifiableInteger packetSize) {
        this.packetSize = packetSize;
    }

    public void setPacketSize(Integer packetSize) {
        this.packetSize = ModifiableVariableFactory.safelySetValue(this.packetSize, packetSize);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

    @Override
    public ChannelOpenConfirmationMessageHandler getHandler(SshContext context) {
        return new ChannelOpenConfirmationMessageHandler(context);
    }

    @Override
    public ChannelOpenConfirmationMessageSerializer getSerializer() {
        return new ChannelOpenConfirmationMessageSerializer(this);
    }

    @Override
    public ChannelOpenConfirmationMessagePreparator getPreparator(SshContext context) {
        return new ChannelOpenConfirmationMessagePreparator(context, this);
    }

}
