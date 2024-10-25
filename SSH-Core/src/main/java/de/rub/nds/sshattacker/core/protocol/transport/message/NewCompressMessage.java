/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.NewCompressMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.NewCompressMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.NewCompressMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.NewCompressMessageSerializer;
import java.io.InputStream;

public class NewCompressMessage extends SshMessage<NewCompressMessage> {

    @Override
    public NewCompressMessageHandler getHandler(SshContext context) {
        return new NewCompressMessageHandler(context);
    }

    @Override
    public NewCompressMessageParser getParser(SshContext context, InputStream stream) {
        return new NewCompressMessageParser(stream);
    }

    @Override
    public NewCompressMessagePreparator getPreparator(SshContext context) {
        return new NewCompressMessagePreparator(context.getChooser(), this);
    }

    @Override
    public NewCompressMessageSerializer getSerializer(SshContext context) {
        return new NewCompressMessageSerializer(this);
    }
}
