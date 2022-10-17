/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.ServerSigAlgsExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.ServerSigAlgsExtensionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;

public class ServerSigAlgsExtensionHandler
        extends AbstractExtensionHandler<ServerSigAlgsExtension> {

    public ServerSigAlgsExtensionHandler(SshContext context) {
        super(context);
    }

    public ServerSigAlgsExtensionHandler(SshContext context, ServerSigAlgsExtension extension) {
        super(context, extension);
    }

    @Override
    public ServerSigAlgsExtensionParser getParser(byte[] array) {
        return new ServerSigAlgsExtensionParser(array);
    }

    @Override
    public ServerSigAlgsExtensionParser getParser(byte[] array, int startPosition) {
        return new ServerSigAlgsExtensionParser(array, startPosition);
    }

    // TODO: Implement Preparator for ServerSigAlgsExtension

    @Override
    public Preparator<ServerSigAlgsExtension> getPreparator() {
        return null;
    }

    @Override
    public ServerSigAlgsExtensionSerializer getSerializer() {
        return new ServerSigAlgsExtensionSerializer(extension);
    }

    // TODO: Implement adjustContext in ServerSigAlgsExtensionHandler !

    @Override
    public void adjustContext() {
        // "server-sig-algs" extension is only sent by server
        if (context.isHandleAsClient()) {

        } else {
            // do nothing
        }
    }
}
