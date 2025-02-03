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
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public abstract class ChannelRequestMessage<T extends ChannelRequestMessage<T>>
        extends ChannelMessage<T> {

    private ModifiableInteger requestTypeLength;
    private ModifiableString requestType;
    private ModifiableByte wantReply;

    protected ChannelRequestMessage() {
        super();
    }

    protected ChannelRequestMessage(ChannelRequestMessage<T> other) {
        super(other);
        requestTypeLength =
                other.requestTypeLength != null ? other.requestTypeLength.createCopy() : null;
        requestType = other.requestType != null ? other.requestType.createCopy() : null;
        wantReply = other.wantReply != null ? other.wantReply.createCopy() : null;
    }

    @Override
    public abstract ChannelRequestMessage<T> createCopy();

    public ModifiableInteger getRequestTypeLength() {
        return requestTypeLength;
    }

    public void setRequestTypeLength(ModifiableInteger requestTypeLength) {
        this.requestTypeLength = requestTypeLength;
    }

    public void setRequestTypeLength(int requestTypeLength) {
        this.requestTypeLength =
                ModifiableVariableFactory.safelySetValue(this.requestTypeLength, requestTypeLength);
    }

    public ModifiableString getRequestType() {
        return requestType;
    }

    public void setRequestType(ModifiableString requestType) {
        setRequestType(requestType, false);
    }

    public void setRequestType(String requestType) {
        setRequestType(requestType, false);
    }

    public void setRequestType(ChannelRequestType requestType) {
        setRequestType(requestType.toString(), false);
    }

    public void setRequestType(ModifiableString requestType, boolean adjustLengthField) {
        this.requestType = requestType;
        if (adjustLengthField) {
            setRequestTypeLength(
                    this.requestType.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setRequestType(String requestType, boolean adjustLengthField) {
        this.requestType = ModifiableVariableFactory.safelySetValue(this.requestType, requestType);
        if (adjustLengthField) {
            setRequestTypeLength(
                    this.requestType.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setSoftlyRequestType(String requestType, boolean adjustLengthField, Config config) {
        this.requestType = ModifiableVariableFactory.softlySetValue(this.requestType, requestType);
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || requestTypeLength == null
                    || requestTypeLength.getOriginalValue() == null) {
                setRequestTypeLength(
                        this.requestType.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
        }
    }

    public void setRequestType(ChannelRequestType requestType, boolean adjustLengthField) {
        setRequestType(requestType.toString(), adjustLengthField);
    }

    public ModifiableByte getWantReply() {
        return wantReply;
    }

    public void setWantReply(ModifiableByte replyWanted) {
        wantReply = replyWanted;
    }

    public void setWantReply(byte wantReply) {
        this.wantReply = ModifiableVariableFactory.safelySetValue(this.wantReply, wantReply);
    }

    public void setSoftlyWantReply(byte wantReply) {
        this.wantReply = ModifiableVariableFactory.softlySetValue(this.wantReply, wantReply);
    }

    public void setWantReply(boolean wantReply) {
        setWantReply(Converter.booleanToByte(wantReply));
    }

    public void setSoftlyWantReply(boolean wantReply) {
        setSoftlyWantReply(Converter.booleanToByte(wantReply));
    }
}
