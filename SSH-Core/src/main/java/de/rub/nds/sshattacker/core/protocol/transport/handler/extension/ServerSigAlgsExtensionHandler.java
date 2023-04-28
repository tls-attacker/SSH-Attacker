/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.protocol.common.Preparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.ServerSigAlgsExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.AbstractExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.ServerSigAlgsExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.ServerSigAlgsExtensionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSigAlgsExtensionHandler
        extends AbstractExtensionHandler<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

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

    @Override
    public AbstractExtensionPreparator<ServerSigAlgsExtension> getPreparator() {
        return new ServerSigAlgsExtensionPreparator(context.getChooser(), extension);
    }

    @Override
    public ServerSigAlgsExtensionSerializer getSerializer() {
        return new ServerSigAlgsExtensionSerializer(extension);
    }

    @Override
    public void adjustContext() {
        // receiving "server-sig-algs" extension as a client -> context has to be updated
        if (context.isHandleAsClient()) {
            context.setServerSupportedPublicKeyAlgorithmsForAuthentification(
                    Converter.nameListToEnumValues(
                            extension.getAcceptedPublicKeyAlgorithms().getValue(),
                            PublicKeyFormat.class));
        }
        // receiving "server-sig-algs" extension as a server -> ignore "server-sig-algs"
        else {
            LOGGER.warn(
                    "Client sent ServerSigAlgsExtension which is supposed to be sent by the server only!");
        }
    }
}
