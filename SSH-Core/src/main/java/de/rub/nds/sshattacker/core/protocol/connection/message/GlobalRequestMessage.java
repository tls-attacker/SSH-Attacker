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
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.Message;

import java.nio.charset.StandardCharsets;

public abstract class GlobalRequestMessage<T extends GlobalRequestMessage<T>> extends Message<T> {

    private ModifiableInteger requestNameLength;
    private ModifiableString requestName;
    private ModifiableByte wantReply;

    protected GlobalRequestMessage(GlobalRequestType requestType) {
        super(MessageIDConstant.SSH_MSG_GLOBAL_REQUEST);
        setRequestName(requestType);
    }

    public ModifiableInteger getRequestNameLength() {
        return requestNameLength;
    }

    public void setRequestNameLength(ModifiableInteger requestNameLength) {
        this.requestNameLength = requestNameLength;
    }

    public void setRequestNameLength(int requestNameLength) {
        this.requestNameLength = ModifiableVariableFactory.safelySetValue(this.requestNameLength, requestNameLength);
    }

    public ModifiableString getRequestName() {
        return requestName;
    }

    public void setRequestName(ModifiableString requestName) {
        setRequestName(requestName, true);
    }

    public void setRequestName(String requestName) {
        setRequestName(requestName, true);
    }

    public void setRequestName(GlobalRequestType requestType) {
        setRequestName(requestType.toString(), true);
    }

    public void setRequestName(ModifiableString requestName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setRequestNameLength(requestName.getValue().getBytes(StandardCharsets.US_ASCII).length);
        }
        this.requestName = requestName;
    }

    public void setRequestName(String requestName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setRequestNameLength(requestName.getBytes(StandardCharsets.US_ASCII).length);
        }
        this.requestName = ModifiableVariableFactory.safelySetValue(this.requestName, requestName);
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
}
