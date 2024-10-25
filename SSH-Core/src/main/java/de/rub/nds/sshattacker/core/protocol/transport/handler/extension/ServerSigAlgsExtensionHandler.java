/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.handler.extension;

import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.AbstractExtension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
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
    public void adjustContext(AbstractExtension<?> extension) {
        adjustContext((ServerSigAlgsExtension) extension);
    }

    @Override
    public void adjustContext(ServerSigAlgsExtension extension) {
        // receiving "server-sig-algs" extension as a client -> context has to be updated
        if (context.isHandleAsClient()) {
            context.setServerSigAlgsExtensionReceivedFromServer(true);
            context.setServerSupportedPublicKeyAlgorithmsForAuthentication(
                    Converter.nameListToEnumValues(
                            extension.getAcceptedPublicKeyAlgorithms().getValue(),
                            PublicKeyAlgorithm.class));
        }
        // receiving "server-sig-algs" extension as a server -> ignore "server-sig-algs"
        else {
            LOGGER.warn(
                    "Client sent ServerSigAlgsExtension which is supposed to be sent by the server only!");
        }
    }
}
