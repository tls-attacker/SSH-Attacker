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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.IgnoreMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.IgnoreMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.IgnoreMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.IgnoreMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.IgnoreMessageSerializer;

import java.io.InputStream;

public class IgnoreMessageSSH1 extends SshMessage<IgnoreMessageSSH1> {

    private ModifiableString ignoreMessage;

    public ModifiableString getIgnoreMessage() {
        return ignoreMessage;
    }

    public void setIgnoreReason(ModifiableString disconnectReason) {
        ignoreMessage = disconnectReason;
    }

    public void setIgnoreReason(String disconnectReason) {
        ignoreMessage =
                ModifiableVariableFactory.safelySetValue(ignoreMessage, disconnectReason);
    }

    @Override
    public IgnoreMessageSSHV1Handler getHandler(SshContext context) {
        return new IgnoreMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<IgnoreMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new IgnoreMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<IgnoreMessageSSH1> getPreparator(SshContext context) {
        return new IgnoreMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<IgnoreMessageSSH1> getSerializer(SshContext context) {
        return new IgnoreMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "Disconnect Message";
    }
}
