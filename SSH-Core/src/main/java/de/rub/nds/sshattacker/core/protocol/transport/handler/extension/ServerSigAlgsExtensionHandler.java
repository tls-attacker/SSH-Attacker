/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.protocol.transport.parser.extension.ServerSigAlgsExtensionParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.extension.ServerSigAlgsExtensionPreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.extension.ServerSigAlgsExtensionSerializer;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSigAlgsExtensionHandler
        extends AbstractExtensionHandler<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public ServerSigAlgsExtensionParser getParser(byte[] array, SshContext context) {
        return new ServerSigAlgsExtensionParser(array);
    }

    @Override
    public ServerSigAlgsExtensionParser getParser(
            byte[] array, int startPosition, SshContext context) {
        return new ServerSigAlgsExtensionParser(array, startPosition);
    }

    public static final ServerSigAlgsExtensionPreparator PREPARATOR =
            new ServerSigAlgsExtensionPreparator();

    public static final ServerSigAlgsExtensionSerializer SERIALIZER =
            new ServerSigAlgsExtensionSerializer();

    @Override
    public void adjustContext(SshContext context, ServerSigAlgsExtension object) {
        // receiving "server-sig-algs" extension as a client -> context has to be updated
        if (context.isHandleAsClient()) {
            context.setServerSigAlgsExtensionReceivedFromServer(true);
            context.setServerSupportedPublicKeyAlgorithmsForAuthentication(
                    Converter.nameListToEnumValues(
                            object.getAcceptedPublicKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
        }
        // receiving "server-sig-algs" extension as a server -> ignore "server-sig-algs"
        else {
            LOGGER.warn(
                    "Client sent ServerSigAlgsExtension which is supposed to be sent by the server only!");
        }
    }
}
