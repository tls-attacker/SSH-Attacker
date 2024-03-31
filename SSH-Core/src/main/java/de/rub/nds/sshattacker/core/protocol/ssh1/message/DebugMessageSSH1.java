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
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.DebugMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.DebugMessageSSHv1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.DebugMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.DebugMessageSSHV1Serializier;
import java.io.InputStream;

public class DebugMessageSSH1 extends Ssh1Message<DebugMessageSSH1> {

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
    public Ssh1MessageParser<DebugMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new DebugMessageSSHv1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<DebugMessageSSH1> getPreparator(SshContext context) {
        return new DebugMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<DebugMessageSSH1> getSerializer(SshContext context) {
        return new DebugMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "Disconnect Message";
    }
}
