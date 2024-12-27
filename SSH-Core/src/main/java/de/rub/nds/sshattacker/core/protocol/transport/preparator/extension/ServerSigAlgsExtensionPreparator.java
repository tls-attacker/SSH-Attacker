/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.ServerSigAlgsExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerSigAlgsExtensionPreparator
        extends AbstractExtensionPreparator<ServerSigAlgsExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ServerSigAlgsExtensionPreparator() {
        super(Extension.SERVER_SIG_ALGS);
    }

    @Override
    public void prepareExtensionSpecificContents(ServerSigAlgsExtension object, Chooser chooser) {
        // sending server-sig-algs extension is not allowed when acting as client
        if (chooser.getContext().isClient()) {
            LOGGER.warn(
                    "Client prepared ServerSigAlgsExtension which is supposed to be sent by the server only!");
        }
        object.setSoftlyAcceptedPublicKeyAlgorithms(
                chooser.getServerSupportedPublicKeyAlgorithmsForAuthentication(),
                true,
                chooser.getConfig());
    }
}
