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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestExecMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestExecMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestExecMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestExecMessageSerializer;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class ChannelRequestExecMessage extends ChannelRequestMessage<ChannelRequestExecMessage> {

    private ModifiableInteger commandLength;
    private ModifiableString command;

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
        this.command = command;
        if (adjustLengthField) {
            setCommandLength(this.command.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    public void setCommand(String command, boolean adjustLengthField) {
        this.command = ModifiableVariableFactory.safelySetValue(this.command, command);
        if (adjustLengthField) {
            setCommandLength(this.command.getValue().getBytes(StandardCharsets.UTF_8).length);
        }
    }

    @Override
    public ChannelRequestExecMessageHandler getHandler(SshContext context) {
        return new ChannelRequestExecMessageHandler(context);
    }

    @Override
    public SshMessageParser<ChannelRequestExecMessage> getParser(
            SshContext context, InputStream stream) {
        return new ChannelRequestExecMessageParser(stream);
    }

    @Override
    public ChannelRequestExecMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestExecMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestExecMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestExecMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "EXEC_MESSAGE";
    }
}
