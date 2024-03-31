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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.IgnoreMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.IgnoreMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.IgnoreMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.IgnoreMessageSSHV1Serializier;
import java.io.InputStream;

public class IgnoreMessageSSH1 extends Ssh1Message<IgnoreMessageSSH1> {

    private ModifiableString ignoreMessage;

    public ModifiableString getIgnoreMessage() {
        return ignoreMessage;
    }

    public void setIgnoreReason(ModifiableString disconnectReason) {
        ignoreMessage = disconnectReason;
    }

    public void setIgnoreReason(String disconnectReason) {
        ignoreMessage = ModifiableVariableFactory.safelySetValue(ignoreMessage, disconnectReason);
    }

    @Override
    public IgnoreMessageSSHV1Handler getHandler(SshContext context) {
        return new IgnoreMessageSSHV1Handler(context);
    }

    @Override
    public Ssh1MessageParser<IgnoreMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new IgnoreMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<IgnoreMessageSSH1> getPreparator(SshContext context) {
        return new IgnoreMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<IgnoreMessageSSH1> getSerializer(SshContext context) {
        return new IgnoreMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "Disconnect Message";
    }
}
