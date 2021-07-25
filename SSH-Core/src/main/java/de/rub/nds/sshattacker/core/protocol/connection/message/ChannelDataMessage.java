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
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.protocol.common.Message;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelDataMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelDataMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelDataMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ChannelDataMessage extends Message<ChannelDataMessage> {

    private ModifiableInteger recipientChannel;
    private ModifiableByteArray data;

    public ChannelDataMessage() {
    }

    public ChannelDataMessage(int recipientChannel, byte[] data) {
        this();
        this.recipientChannel = ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    public ModifiableInteger getRecipientChannel() {
        return recipientChannel;
    }

    public void setRecipientChannel(ModifiableInteger recipientChannel) {
        this.recipientChannel = recipientChannel;
    }

    public void setRecipientChannel(int recipientChannel) {
        this.recipientChannel = ModifiableVariableFactory.safelySetValue(this.recipientChannel, recipientChannel);
    }

    public ModifiableByteArray getData() {
        return data;
    }

    public void setData(ModifiableByteArray data) {
        this.data = data;
    }

    public void setData(byte[] data) {
        this.data = ModifiableVariableFactory.safelySetValue(this.data, data);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

    @Override
    public ChannelDataMessageHandler getHandler(SshContext context) {
        return new ChannelDataMessageHandler(context);
    }

    @Override
    public ChannelDataMessageSerializer getSerializer() {
        return new ChannelDataMessageSerializer(this);
    }

    @Override
    public ChannelDataMessagePreparator getPreparator(SshContext context) {
        return new ChannelDataMessagePreparator(context, this);
    }
}
