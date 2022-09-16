/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.DelayCompressionExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.DelayCompressionExtensionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class DelayCompressionExtensionHandler
        extends AbstractExtensionHandler<DelayCompressionExtension> {

    public DelayCompressionExtensionHandler(SshContext context) {
        super(context);
    }

    public DelayCompressionExtensionHandler(
            SshContext context, DelayCompressionExtension extension) {
        super(context, extension);
    }

    @Override
    public void adjustContext() {
        // TODO: Handle DelayCompressionExtension
    }

    @Override
    public DelayCompressionExtensionParser getParser(byte[] array) {
        return new DelayCompressionExtensionParser(array);
    }

    @Override
    public DelayCompressionExtensionParser getParser(byte[] array, int startPosition) {
        return new DelayCompressionExtensionParser(array, startPosition);
    }

    @Override
    public Preparator<DelayCompressionExtension> getPreparator() {
        return null;
    }

    @Override
    public DelayCompressionExtensionSerializer getSerializer() {
        return new DelayCompressionExtensionSerializer(extension);
    }
}
