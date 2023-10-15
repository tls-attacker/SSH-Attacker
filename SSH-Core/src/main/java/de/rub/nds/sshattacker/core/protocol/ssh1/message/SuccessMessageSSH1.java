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
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.SuccessMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.SuccessMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.SuccessMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.SuccessMessageSerializier;
import java.io.InputStream;

public class SuccessMessageSSH1 extends SshMessage<SuccessMessageSSH1> {

    @Override
    public SuccessMessageHandler getHandler(SshContext context) {
        return new SuccessMessageHandler(context);
    }

    @Override
    public SshMessageParser<SuccessMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new SuccessMessageParser(context, stream);
    }

    @Override
    public SshMessagePreparator<SuccessMessageSSH1> getPreparator(SshContext context) {
        return new SuccessMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<SuccessMessageSSH1> getSerializer(SshContext context) {
        return new SuccessMessageSerializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_SMSG_SUCCESS";
    }
}
