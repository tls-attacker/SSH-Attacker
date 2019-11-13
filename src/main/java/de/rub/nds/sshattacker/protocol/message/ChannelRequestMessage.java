package de.rub.nds.sshattacker.protocol.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.protocol.core.message.Serializer;
import de.rub.nds.sshattacker.protocol.handler.ChannelRequestMessageHandler;
import de.rub.nds.sshattacker.protocol.handler.Handler;
import de.rub.nds.sshattacker.protocol.preparator.ChannelRequestMessagePreparator;
import de.rub.nds.sshattacker.protocol.preparator.Preparator;
import de.rub.nds.sshattacker.protocol.serializer.ChannelRequestMessageSerializer;
import de.rub.nds.sshattacker.state.SshContext;

public class ChannelRequestMessage extends Message {

    private ModifiableInteger recipientChannel;
    private ModifiableString requestType;
    private ModifiableByte replyWanted;
    private ModifiableByteArray payload;

    public ChannelRequestMessage() {
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

    public ModifiableString getRequestType() {
        return requestType;
    }

    public void setRequestType(ModifiableString requestType) {
        this.requestType = requestType;
    }

    public void setRequestType(String requestType) {
        this.requestType = ModifiableVariableFactory.safelySetValue(this.requestType, requestType);
    }

    public ModifiableByte getReplyWanted() {
        return replyWanted;
    }

    public void setReplyWanted(ModifiableByte replyWanted) {
        this.replyWanted = replyWanted;
    }

    public void setReplyWanted(byte replyWanted) {
        this.replyWanted = ModifiableVariableFactory.safelySetValue(this.replyWanted, replyWanted);
    }

    public ModifiableByteArray getPayload() {
        return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    @Override
    public String toCompactString() {
        return this.getClass().getSimpleName();
    }

    @Override
    public Handler getHandler(SshContext context) {
        return new ChannelRequestMessageHandler(context);
    }

    @Override
    public Serializer getSerializer() {
        return new ChannelRequestMessageSerializer(this);
    }

    @Override
    public Preparator getPreparator(SshContext context) {
        return new ChannelRequestMessagePreparator(context, this);
    }
}
