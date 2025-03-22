/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.UnknownExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.UnknownExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.UnknownExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.UnknownExtensionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class UnknownExtensionHandler extends AbstractExtensionHandler<UnknownExtension> {

    @Override
    public void adjustContext(SshContext context, UnknownExtension object) {
        // TODO: Handle UnknownExtension
    }

    @Override
    public UnknownExtensionParser getParser(byte[] array, SshContext context) {
        return new UnknownExtensionParser(array);
    }

    @Override
    public UnknownExtensionParser getParser(byte[] array, int startPosition, SshContext context) {
        return new UnknownExtensionParser(array, startPosition);
    }

    public static final UnknownExtensionPreparator PREPARATOR = new UnknownExtensionPreparator();

    public static final UnknownExtensionSerializer SERIALIZER = new UnknownExtensionSerializer();
}
