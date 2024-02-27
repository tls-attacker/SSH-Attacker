/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.DebugMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.DebugMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.DebugMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.DebugMessageSSHV1Serializier;
import java.io.InputStream;

public class DebugMessageSSH1 extends SshMessage<DebugMessageSSH1> {

    private ModifiableString debugMessage;

    public ModifiableString getDebugMessage() {
        return debugMessage;
    }

    public void setDebugMessage(ModifiableString disconnectReason) {
        debugMessage = disconnectReason;
    }

    public void setDebugMessage(String disconnectReason) {
        debugMessage = ModifiableVariableFactory.safelySetValue(debugMessage, disconnectReason);
    }

    @Override
    public DebugMessageSSHV1Handler getHandler(SshContext context) {
        return new DebugMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<DebugMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new DebugMessageSSHv1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<DebugMessageSSH1> getPreparator(SshContext context) {
        return new DebugMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<DebugMessageSSH1> getSerializer(SshContext context) {
        return new DebugMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "Disconnect Message";
    }
}
