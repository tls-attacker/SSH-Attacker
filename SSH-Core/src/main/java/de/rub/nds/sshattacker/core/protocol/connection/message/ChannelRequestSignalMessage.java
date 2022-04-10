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
import de.rub.nds.sshattacker.core.constants.SignalType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestSignalMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelRequestSignalMessage
        extends ChannelRequestMessage<ChannelRequestSignalMessage> {

    private ModifiableInteger signalNameLength;
    private ModifiableString signalName;

    public ChannelRequestSignalMessage() {
        super(ChannelRequestType.SIGNAL);
    }

    public ChannelRequestSignalMessage(Integer senderChannel) {
        super(ChannelRequestType.SIGNAL, senderChannel);
    }

    public ChannelRequestSignalMessage(Integer senderChannel, String signalName) {
        super(ChannelRequestType.SIGNAL, senderChannel);
    }

    @Override
    public ChannelRequestSignalMessageHandler getHandler(SshContext context) {
        return new ChannelRequestSignalMessageHandler(context, this);
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
        if (adjustLengthField) {
            setSignalNameLength(signalName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.signalName = signalName;
    }

    public void setSignalName(String signalName, boolean adjustLengthField) {
        if (adjustLengthField) {
            setSignalNameLength(signalName.getBytes(StandardCharsets.UTF_8).length);
        }
        this.signalName = ModifiableVariableFactory.safelySetValue(this.signalName, signalName);
    }

    public void setSignalName(SignalType signalName, boolean adjustLengthField) {
        setSignalName(signalName.toString(), adjustLengthField);
    }
}
