/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.FailureMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.SuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.FailureMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.SuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.FailureMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.SuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.FailureMessageSerializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.SuccessMessageSerializier;

import java.io.InputStream;

public class FailureMessageSSH1 extends SshMessage<FailureMessageSSH1> {

    @Override
    public FailureMessageHandler getHandler(SshContext context) {
        return new FailureMessageHandler(context);
    }

    @Override
    public SshMessageParser<FailureMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new FailureMessageParser(context, stream);
    }

    @Override
    public SshMessagePreparator<FailureMessageSSH1> getPreparator(SshContext context) {
        return new FailureMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<FailureMessageSSH1> getSerializer(SshContext context) {
        return new FailureMessageSerializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_SMSG_FAILURE";
    }
}
