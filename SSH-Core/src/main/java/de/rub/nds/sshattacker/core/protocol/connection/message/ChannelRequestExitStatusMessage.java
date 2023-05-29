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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.connection.handler.ChannelRequestExitStatusMessageHandler;
import de.rub.nds.sshattacker.core.protocol.connection.parser.ChannelRequestExitStatusMessageParser;
import de.rub.nds.sshattacker.core.protocol.connection.preparator.ChannelRequestExitStatusMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.serializer.ChannelRequestExitStatusMessageSerializer;
import java.io.InputStream;

public class ChannelRequestExitStatusMessage
        extends ChannelRequestMessage<ChannelRequestExitStatusMessage> {

    private ModifiableInteger exitStatus;

    public ModifiableInteger getExitStatus() {
        return exitStatus;
    }

    public void setExitStatus(ModifiableInteger exitStatus) {
        this.exitStatus = exitStatus;
    }

    public void setExitStatus(int exitStatus) {
        this.exitStatus = ModifiableVariableFactory.safelySetValue(this.exitStatus, exitStatus);
    }

    @Override
    public ChannelRequestExitStatusMessageHandler getHandler(SshContext context) {
        return new ChannelRequestExitStatusMessageHandler(context);
    }

    @Override
    public ChannelRequestExitStatusMessageParser getParser(SshContext context, InputStream stream) {
        return new ChannelRequestExitStatusMessageParser(stream);
    }

    @Override
    public ChannelRequestExitStatusMessagePreparator getPreparator(SshContext context) {
        return new ChannelRequestExitStatusMessagePreparator(context.getChooser(), this);
    }

    @Override
    public ChannelRequestExitStatusMessageSerializer getSerializer(SshContext context) {
        return new ChannelRequestExitStatusMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "EXIT_STATUS";
    }
}
