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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.EofMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ExitConfirmationMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.EofMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ExitConfirmationMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.EofMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ExitConfirmationMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.EofMessageSSHV1Serializier;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ExitConfirmationMessageSSHV1Serializier;

import java.io.InputStream;

public class ExitConfirmationMessageSSH1 extends SshMessage<ExitConfirmationMessageSSH1> {

    @Override
    public ExitConfirmationMessageSSHV1Handler getHandler(SshContext context) {
        return new ExitConfirmationMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<ExitConfirmationMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new ExitConfirmationMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<ExitConfirmationMessageSSH1> getPreparator(SshContext context) {
        return new ExitConfirmationMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<ExitConfirmationMessageSSH1> getSerializer(SshContext context) {
        return new ExitConfirmationMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
