/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.EofMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.EofMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.EofMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.EofMessageSSHV1Serializier;
import java.io.InputStream;

public class EofMessageSSH1 extends Ssh1Message<EofMessageSSH1> {

    @Override
    public EofMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new EofMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<EofMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new EofMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<EofMessageSSH1> getPreparator(SshContext sshContext) {
        return new EofMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<EofMessageSSH1> getSerializer(SshContext sshContext) {
        return new EofMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_EOF";
    }
}
