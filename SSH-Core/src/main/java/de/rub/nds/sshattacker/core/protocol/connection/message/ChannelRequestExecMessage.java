/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.ChannelRequestType;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestExecMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.nio.charset.StandardCharsets;

public class ChannelRequestExecMessage extends ChannelRequestMessage<ChannelRequestExecMessage> {

    private ModifiableInteger commandLength;
    private ModifiableString command;

    public ChannelRequestExecMessage() {
        super(ChannelRequestType.EXEC);
    }

    public ChannelRequestExecMessage(String command) {
        super(ChannelRequestType.EXEC);
        setCommand(command, true);
    }

    public ModifiableInteger getCommandLength() {
        return commandLength;
    }

    public void setCommandLength(ModifiableInteger commandLength) {
        this.commandLength = commandLength;
    }

    public void setCommandLength(int commandLength) {
        this.commandLength =
                ModifiableVariableFactory.safelySetValue(this.commandLength, commandLength);
    }

    public ModifiableString getCommand() {
        return command;
    }

    public void setCommand(ModifiableString command) {
        setCommand(command, false);
    }

    public void setCommand(String command) {
        setCommand(command, false);
    }

    public void setCommand(ModifiableString command, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCommandLength(command.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
        this.command = command;
    }

    public void setCommand(String command, boolean adjustLengthField) {
        if (adjustLengthField) {
            setCommandLength(command.getBytes(StandardCharsets.UTF_8).length);
        }
        this.command = ModifiableVariableFactory.safelySetValue(this.command, command);
    }

    @Override
    public ChannelRequestExecMessageHandler getHandler(SshContext context) {
        return new ChannelRequestExecMessageHandler(context, this);
    }
}
