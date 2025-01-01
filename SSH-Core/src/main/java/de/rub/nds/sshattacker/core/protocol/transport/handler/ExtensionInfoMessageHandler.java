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

    @Override
    public void adjustContext(SshContext context, ExtensionInfoMessage object) {
        if (context.isHandleAsClient()) {
            context.setServerSupportedExtensions(object.getExtensions());
        } else {
            context.setClientSupportedExtensions(object.getExtensions());
        }
        object.getExtensions().forEach(extension -> extension.adjustContext(context));
    }

    @Override
    public ExtensionInfoMessageParser getParser(byte[] array, SshContext context) {
        return new ExtensionInfoMessageParser(array);
    }

    @Override
    public ExtensionInfoMessageParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ExtensionInfoMessageParser(array, startPosition);
    }

    public static final ExtensionInfoMessagePreparator PREPARATOR =
            new ExtensionInfoMessagePreparator();

    public static final ExtensionInfoMessageSerializer SERIALIZER =
            new ExtensionInfoMessageSerializer();
}
