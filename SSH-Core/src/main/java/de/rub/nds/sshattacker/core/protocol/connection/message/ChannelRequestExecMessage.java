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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.HasSentHandler;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestExecMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;

public class ChannelRequestExecMessage extends ChannelRequestMessage<ChannelRequestExecMessage>
        implements HasSentHandler {

    private ModifiableInteger commandLength;
    private ModifiableString command;

    public ChannelRequestExecMessage() {
        super();
    }

    public ChannelRequestExecMessage(ChannelRequestExecMessage other) {
        super(other);
        commandLength = other.commandLength != null ? other.commandLength.createCopy() : null;
        command = other.command != null ? other.command.createCopy() : null;
    }

    @Override
    public ChannelRequestExecMessage createCopy() {
        return new ChannelRequestExecMessage(this);
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

    public void setSoftlyCommand(String command, boolean adjustLengthField, Config config) {
        if (this.command == null || this.command.getOriginalValue() == null) {
            this.command = ModifiableVariableFactory.safelySetValue(this.command, command);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || commandLength == null
                    || commandLength.getOriginalValue() == null) {
                setCommandLength(this.command.getValue().getBytes(StandardCharsets.UTF_8).length);
            }
        }
    }

    public static final ChannelRequestExecMessageHandler HANDLER =
            new ChannelRequestExecMessageHandler();

    @Override
    public ChannelRequestExecMessageHandler getHandler() {
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
        ChannelRequestExecMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return ChannelRequestExecMessageHandler.SERIALIZER.serialize(this);
    }
}
