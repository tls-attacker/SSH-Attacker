package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.ChannelDataMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelDataMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelDataMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelDataMessage extends Message {

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
    public Handler getHandler(SshContext context) {
        return new ChannelDataMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ChannelDataMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ChannelDataMessagePreparator(context, this);
    }
}
