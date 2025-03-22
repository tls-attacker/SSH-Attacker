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
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestEnvMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelRequestEnvMessage extends ChannelRequestMessage<ChannelRequestEnvMessage>
        implements HasSentHandler {

    private ModifiableString variableName;
    private ModifiableInteger variableNameLength;
    private ModifiableString variableValue;
    private ModifiableInteger variableValueLength;

    public ChannelRequestEnvMessage() {
        super();
    }

    public ChannelRequestEnvMessage(ChannelRequestEnvMessage other) {
        super(other);
        variableName = other.variableName != null ? other.variableName.createCopy() : null;
        variableNameLength =
                other.variableNameLength != null ? other.variableNameLength.createCopy() : null;
        variableValue = other.variableValue != null ? other.variableValue.createCopy() : null;
        variableValueLength =
                other.variableValueLength != null ? other.variableValueLength.createCopy() : null;
    }

    @Override
    public ChannelRequestEnvMessage createCopy() {
        return new ChannelRequestEnvMessage(this);
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
        this.variableName = variableName;
        if (adjustLengthField) {
            setVariableNameLength(
                    this.variableName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setVariableName(String variableName, boolean adjustLengthField) {
        this.variableName =
                ModifiableVariableFactory.safelySetValue(this.variableName, variableName);
        if (adjustLengthField) {
            setVariableNameLength(
                    this.variableName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
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
        this.variableValue = variableValue;
        if (adjustLengthField) {
            setVariableValueLength(
                    this.variableValue.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setVariableValue(String variableValue, boolean adjustLengthField) {
        this.variableValue =
                ModifiableVariableFactory.safelySetValue(this.variableValue, variableValue);
        if (adjustLengthField) {
            setVariableValueLength(
                    this.variableValue.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
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

    public static final ChannelRequestEnvMessageHandler HANDLER =
            new ChannelRequestEnvMessageHandler();

    @Override
    public ChannelRequestEnvMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void adjustContextAfterSent(SshContext context) {
        HANDLER.adjustContextAfterMessageSent(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        ChannelRequestEnvMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestEnvMessageHandler.SERIALIZER.serialize(this);
    }
}
