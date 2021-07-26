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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.util.Converter;

import java.nio.charset.StandardCharsets;

public abstract class ChannelRequestMessage<T extends ChannelRequestMessage<T>> extends ChannelMessage<T> {

    private ModifiableInteger requestTypeLength;
    private ModifiableString requestType;
    private ModifiableByte wantReply;

    protected ChannelRequestMessage(ChannelRequestType requestType) {
        super(MessageIDConstant.SSH_MSG_CHANNEL_REQUEST);
        setRequestType(requestType);
    }

    public ModifiableInteger getRequestTypeLength() {
        return requestTypeLength;
    }

    public void setRequestTypeLength(ModifiableInteger requestTypeLength) {
        this.requestTypeLength = requestTypeLength;
    }

    public void setRequestTypeLength(int requestTypeLength) {
        this.requestTypeLength = ModifiableVariableFactory.safelySetValue(this.requestTypeLength, requestTypeLength);
    }

    public ModifiableString getRequestType() {
        return requestType;
    }

    public void setRequestType(ModifiableString requestType) {
        setRequestType(requestType, true);
    }

    public void setRequestType(String requestType) {
        setRequestType(requestType, true);
    }

    public void setRequestType(ChannelRequestType requestType) {
        setRequestType(requestType.toString(), true);
    }

    public void setRequestType(ModifiableString requestType, boolean adjustLengthField) {
        if (adjustLengthField) {
            setRequestTypeLength(requestType.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.requestType = requestType;
    }

    public void setRequestType(String requestType, boolean adjustLengthField) {
        if (adjustLengthField) {
            setRequestTypeLength(requestType.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.requestType = ModifiableVariableFactory.safelySetValue(this.requestType, requestType);
    }

    public void setRequestType(ChannelRequestType requestType, boolean adjustLengthField) {
        setRequestType(requestType.toString(), adjustLengthField);
    }

    public ModifiableByte getWantReply() {
        return wantReply;
    }

    public void setWantReply(ModifiableByte replyWanted) {
        this.wantReply = replyWanted;
    }

    public void setWantReply(byte wantReply) {
        this.wantReply = ModifiableVariableFactory.safelySetValue(this.wantReply, wantReply);
    }

    public void setWantReply(boolean wantReply) {
        setWantReply(Converter.booleanToByte(wantReply));
    }
}
