/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.transport.parser.ExtensionInfoMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.ExtensionInfoMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.ExtensionInfoMessageSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ExtensionInfoMessageHandler extends SshMessageHandler<ExtensionInfoMessage> {

    public ExtensionInfoMessageHandler(SshContext context) {
        super(context);
    }

    public ExtensionInfoMessageHandler(SshContext context, ExtensionInfoMessage message) {
        super(context, message);
    }

    @Override
    public void adjustContext() {
        if (context.isHandleAsClient()) {
            context.setServerSupportedExtensions(message.getExtensions());
        } else {
            context.setClientSupportedExtensions(message.getExtensions());
        }
        message.getExtensions().forEach(extension -> extension.getHandler(context).adjustContext());
    }

    @Override
    public ExtensionInfoMessageParser getParser(byte[] array) {
        return new ExtensionInfoMessageParser(array);
    }

    @Override
    public ExtensionInfoMessageParser getParser(byte[] array, int startPosition) {
        return new ExtensionInfoMessageParser(array, startPosition);
    }

    public static final ExtensionInfoMessagePreparator PREPARATOR =
            new ExtensionInfoMessagePreparator();

    public static final ExtensionInfoMessageSerializer SERIALIZER =
            new ExtensionInfoMessageSerializer();
}
