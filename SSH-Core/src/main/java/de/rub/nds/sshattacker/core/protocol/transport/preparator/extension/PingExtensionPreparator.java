/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.PingExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PingExtensionPreparator extends AbstractExtensionPreparator<PingExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PingExtensionPreparator() {
        super(Extension.PING_OPENSSH_COM);
    }

    @Override
    protected void prepareExtensionSpecificContents(PingExtension object, Chooser chooser) {
        // Sending ping@openssh.com is not allowed by the client according to OpenSSH specs
        if (chooser.getContext().isClient()) {
            LOGGER.warn(
                    "Client prepared PingExtension which is supposed to be sent by the server only!");
        }
        object.setVersion("0", true);
    }
}
