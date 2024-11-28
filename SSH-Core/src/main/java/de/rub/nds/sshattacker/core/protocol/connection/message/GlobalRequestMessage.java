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
import de.rub.nds.sshattacker.core.constants.GlobalRequestType;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import java.nio.charset.StandardCharsets;

public abstract class GlobalRequestMessage<T extends GlobalRequestMessage<T>>
        extends SshMessage<T> {

    private ModifiableInteger requestNameLength;
    private ModifiableString requestName;
    private ModifiableByte wantReply;

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

    public void setSoftlyRequestName(String requestName, boolean adjustLengthField, Config config) {
        if (this.requestName == null || this.requestName.getOriginalValue() == null) {
            this.requestName =
                    ModifiableVariableFactory.safelySetValue(this.requestName, requestName);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || requestNameLength == null
                    || requestNameLength.getOriginalValue() == null) {
                setRequestNameLength(
                        this.requestName.getValue().getBytes(StandardCharsets.US_ASCII).length);
            }
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

    public void setSoftlyWantReply(byte wantReply) {
        if (this.wantReply == null || this.wantReply.getOriginalValue() == null) {
            this.wantReply = ModifiableVariableFactory.safelySetValue(this.wantReply, wantReply);
        }
    }

    public void setWantReply(boolean wantReply) {
        setWantReply(Converter.booleanToByte(wantReply));
    }
}
