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
import java.math.BigInteger;

public class ExtensionInfoMessageHandler extends SshMessageHandler<ExtensionInfoMessage> {

    public ExtensionInfoMessageHandler(SshContext context) {
        super(context);
    }

    public ExtensionInfoMessageHandler(SshContext context, ExtensionInfoMessage message) {
        super(context, message);
    }

    @Override
    public ExtensionInfoMessageParser getParser(byte[] array) {
        return new ExtensionInfoMessageParser(array);
    }

    @Override
    public ExtensionInfoMessageParser getParser(byte[] array, int startPosition) {
        return new ExtensionInfoMessageParser(array, startPosition);
    }

    @Override
    public ExtensionInfoMessagePreparator getPreparator() {
        return new ExtensionInfoMessagePreparator(context.getChooser(), message);
    }

    @Override
    public ExtensionInfoMessageSerializer getSerializer() {
        return new ExtensionInfoMessageSerializer(message);
    }

    // TODO: Search for "ext-info-s" or "ext-info-c" in SSH_MSG_KEXINIT

    @Override
    public void adjustContext() {
        // we received an SSH_MSG_EXT_INFO being a client
        if (context.isHandleAsClient()) {
            context.setNumberExtensionsOfServer(
                    new BigInteger(message.getNumberExtensions().getValue()).intValue());

            context.setExtensionsOfServer(message.getExtensions());
        }
        // we received an SSH_MSG_EXT_INFO being a server
        else {
            context.setNumberExtensionsOfClient(
                    new BigInteger(message.getNumberExtensions().getValue()).intValue());

            context.setExtensionsOfClient(message.getExtensions());
        }
    }
}
