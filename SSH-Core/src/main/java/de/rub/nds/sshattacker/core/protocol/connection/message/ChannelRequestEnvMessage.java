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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestEnvMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelRequestEnvMessage extends ChannelRequestMessage<ChannelRequestEnvMessage> {

    ModifiableString variableName;
    String transferVariableName;
    ModifiableInteger variableNameLength;
    ModifiableString variableValue;
    String transferVariableValue;
    ModifiableInteger variableValueLength;

    public ChannelRequestEnvMessage() {
        super(ChannelRequestType.ENV);
    }

    public ChannelRequestEnvMessage(Integer senderChannel) {
        super(ChannelRequestType.ENV, senderChannel);
    }

    public ChannelRequestEnvMessage(
            Integer senderChannel, String variableName, String variableValue) {
        super(ChannelRequestType.ENV, senderChannel);
        setTransferVariableName(variableName);
        setTransferVariableValue(variableValue);
    }

    public ModifiableString getVariableName() {
        return variableName;
    }

    public void setVariableName(ModifiableString variableName) {
        this.variableName = variableName;
    }

    public void setVariableName(String variableName) {
        this.variableName =
                ModifiableVariableFactory.safelySetValue(this.variableName, variableName);
    }

    public void setVariableName(ModifiableString variableName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVariableNameLength(variableName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.variableName = variableName;
    }

    public void setVariableName(String variableName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVariableNameLength(variableName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.variableName =
                ModifiableVariableFactory.safelySetValue(this.variableName, variableName);
    }

    public ModifiableInteger getVariableNameLength() {
        return variableNameLength;
    }

    public void setVariableNameLength(ModifiableInteger variableNameLength) {
        this.variableNameLength = variableNameLength;
    }

    public void setVariableNameLength(int variableNameLength) {
        this.variableNameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.variableNameLength, variableNameLength);
    }

    public ModifiableString getVariableValue() {
        return variableValue;
    }

    public void setVariableValue(ModifiableString variableValue) {
        this.variableValue = variableValue;
    }

    public void setVariableValue(String variableValue) {
        this.variableValue =
                ModifiableVariableFactory.safelySetValue(this.variableValue, variableValue);
    }

    public void setVariableValue(ModifiableString variableValue, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVariableValueLength(
                    variableValue.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.variableValue = variableValue;
    }

    public void setVariableValue(String variableValue, boolean adjustLengthField) {
        if (adjustLengthField) {
            setVariableValueLength(variableValue.getBytes(StandardCharsets.UTF_8).length);
        }
        this.variableValue =
                ModifiableVariableFactory.safelySetValue(this.variableValue, variableValue);
    }

    public ModifiableInteger getVariableValueLength() {
        return variableValueLength;
    }

    public void setVariableValueLength(ModifiableInteger variableValueLength) {
        this.variableValueLength = variableValueLength;
    }

    public void setVariableValueLength(int variableValueLength) {
        this.variableValueLength =
                ModifiableVariableFactory.safelySetValue(
                        this.variableValueLength, variableValueLength);
    }

    public String getTransferVariableName() {
        return transferVariableName;
    }

    public void setTransferVariableName(String transferVariableName) {
        this.transferVariableName = transferVariableName;
    }

    public String getTransferVariableValue() {
        return transferVariableValue;
    }

    public void setTransferVariableValue(String transferVariableValue) {
        this.transferVariableValue = transferVariableValue;
    }

    @Override
    public ChannelRequestEnvMessageHandler getHandler(SshContext context) {
        return new ChannelRequestEnvMessageHandler(context, this);
    }
}
