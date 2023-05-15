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
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestSubsystemMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.nio.charset.StandardCharsets;

public class ChannelRequestSubsystemMessage
        extends ChannelRequestMessage<ChannelRequestSubsystemMessage> {

    private ModifiableInteger subsystemNameLength;
    private ModifiableString subsystemName;

    public ModifiableInteger getSubsystemNameLength() {
        return subsystemNameLength;
    }

    public void setSubsystemNameLength(ModifiableInteger subsystemNameLength) {
        this.subsystemNameLength = subsystemNameLength;
    }

    public void setSubsystemNameLength(int subsystemNameLength) {
        this.subsystemNameLength =
                ModifiableVariableFactory.safelySetValue(
                        this.subsystemNameLength, subsystemNameLength);
    }

    public ModifiableString getSubsystemName() {
        return subsystemName;
    }

    public void setSubsystemName(ModifiableString subsystemName) {
        this.subsystemName = subsystemName;
    }

    public void setSubsystemName(String subsystemName) {
        this.subsystemName =
                ModifiableVariableFactory.safelySetValue(this.subsystemName, subsystemName);
    }

    public void setSubsystemName(ModifiableString subsystemName, boolean adjustLengthField) {
        this.subsystemName = subsystemName;
        if (adjustLengthField) {
            setSubsystemNameLength(
                    this.subsystemName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setSubsystemName(String subsystemName, boolean adjustLengthField) {
        this.subsystemName =
                ModifiableVariableFactory.safelySetValue(this.subsystemName, subsystemName);
        if (adjustLengthField) {
            setSubsystemNameLength(
                    this.subsystemName.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    @Override
    public ChannelRequestSubsystemMessageHandler getHandler(SshContext context) {
        return new ChannelRequestSubsystemMessageHandler(context, this);
    }
}
