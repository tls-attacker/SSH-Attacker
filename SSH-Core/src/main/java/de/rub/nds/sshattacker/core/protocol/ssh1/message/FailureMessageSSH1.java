/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.FailureMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.FailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.FailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.FailureMessageSerializier;
import java.io.InputStream;

public class FailureMessageSSH1 extends Ssh1Message<FailureMessageSSH1> {

    @Override
    public FailureMessageHandler getHandler(SshContext context) {
        return new FailureMessageHandler(context);
    }

    @Override
    public Ssh1MessageParser<FailureMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new FailureMessageParser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<FailureMessageSSH1> getPreparator(SshContext context) {
        return new FailureMessagePreparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<FailureMessageSSH1> getSerializer(SshContext context) {
        return new FailureMessageSerializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_SMSG_FAILURE";
    }
}
