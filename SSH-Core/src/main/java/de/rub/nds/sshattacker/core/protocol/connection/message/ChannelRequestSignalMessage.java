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
import de.rub.nds.sshattacker.core.constants.SignalType;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestSignalMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelRequestSignalMessage extends ChannelRequestMessage<ChannelRequestSignalMessage>
        implements HasSentHandler {

    private ModifiableInteger signalNameLength;
    private ModifiableString signalName;

    public ChannelRequestSignalMessage() {
        super();
    }

    public ChannelRequestSignalMessage(ChannelRequestSignalMessage other) {
        super(other);
        signalNameLength =
                other.signalNameLength != null ? other.signalNameLength.createCopy() : null;
        signalName = other.signalName != null ? other.signalName.createCopy() : null;
    }

    @Override
    public ChannelRequestSignalMessage createCopy() {
        return new ChannelRequestSignalMessage(this);
    }

    public ModifiableInteger getSignalNameLength() {
        return signalNameLength;
    }

    public void setSignalNameLength(ModifiableInteger signalNameLength) {
        this.signalNameLength = signalNameLength;
    }

    public void setSignalNameLength(int signalNameLength) {
        this.signalNameLength =
                ModifiableVariableFactory.safelySetValue(this.signalNameLength, signalNameLength);
    }

    public ModifiableString getSignalName() {
        return signalName;
    }

    public void setSignalName(ModifiableString signalName) {
        this.signalName = signalName;
    }

    public void setSignalName(String signalName) {
        this.signalName = ModifiableVariableFactory.safelySetValue(this.signalName, signalName);
    }

    public void setSignalName(SignalType signalType) {
        setSignalName(signalType.toString());
    }

    public void setSignalName(ModifiableString signalName, boolean adjustLengthField) {
        this.signalName = signalName;
        if (adjustLengthField) {
            setSignalNameLength(this.signalName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSignalName(String signalName, boolean adjustLengthField) {
        this.signalName = ModifiableVariableFactory.safelySetValue(this.signalName, signalName);
        if (adjustLengthField) {
            setSignalNameLength(this.signalName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSignalName(SignalType signalName, boolean adjustLengthField) {
        setSignalName(signalName.toString(), adjustLengthField);
    }

    public static final ChannelRequestSignalMessageHandler HANDLER =
            new ChannelRequestSignalMessageHandler();

    @Override
    public ChannelRequestSignalMessageHandler getHandler() {
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
        ChannelRequestSignalMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestSignalMessageHandler.SERIALIZER.serialize(this);
    }
}
