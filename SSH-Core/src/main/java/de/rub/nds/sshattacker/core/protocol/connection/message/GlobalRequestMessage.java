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
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public abstract class GlobalRequestMessage<T extends GlobalRequestMessage<T>>
        extends SshMessage<T> {

    private ModifiableInteger requestNameLength;
    private ModifiableString requestName;
    private ModifiableByte wantReply;

    protected GlobalRequestMessage() {
        super();
    }

    protected GlobalRequestMessage(GlobalRequestMessage<T> other) {
        super(other);
        requestNameLength =
                other.requestNameLength != null ? other.requestNameLength.createCopy() : null;
        requestName = other.requestName != null ? other.requestName.createCopy() : null;
        wantReply = other.wantReply != null ? other.wantReply.createCopy() : null;
    }

    @Override
    public abstract GlobalRequestMessage<T> createCopy();

    public ModifiableInteger getRequestNameLength() {
        return requestNameLength;
    }

    public void setRequestNameLength(ModifiableInteger requestNameLength) {
        this.requestNameLength = requestNameLength;
    }

    public void setRequestNameLength(int requestNameLength) {
        this.requestNameLength =
                ModifiableVariableFactory.safelySetValue(this.requestNameLength, requestNameLength);
    }

    public ModifiableString getRequestName() {
        return requestName;
    }

    public void setRequestName(ModifiableString requestName) {
        setRequestName(requestName, false);
    }

    public void setRequestName(String requestName) {
        setRequestName(requestName, false);
    }

    public void setRequestName(GlobalRequestType requestType) {
        setRequestName(requestType.toString(), false);
    }

    public void setRequestName(ModifiableString requestName, boolean adjustLengthField) {
        this.requestName = requestName;
        if (adjustLengthField) {
            setRequestNameLength(
                    this.requestName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setRequestName(String requestName, boolean adjustLengthField) {
        this.requestName = ModifiableVariableFactory.safelySetValue(this.requestName, requestName);
        if (adjustLengthField) {
            setRequestNameLength(
                    this.requestName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
    }

    public void setRequestName(GlobalRequestType requestType, boolean adjustLengthField) {
        setRequestName(requestType.toString(), adjustLengthField);
    }

    public ModifiableByte getWantReply() {
        return wantReply;
    }

    public void setWantReply(ModifiableByte wantReply) {
        this.wantReply = wantReply;
    }

    public void setWantReply(byte wantReply) {
        this.wantReply = ModifiableVariableFactory.safelySetValue(this.wantReply, wantReply);
    }

    public void setWantReply(boolean wantReply) {
        setWantReply(Converter.booleanToByte(wantReply));
    }
}
