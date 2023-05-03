/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DelayCompressionExtensionPreparator
        extends AbstractExtensionPreparator<DelayCompressionExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DelayCompressionExtensionPreparator(
            Chooser chooser, DelayCompressionExtension extension) {
        super(chooser, extension);
    }

    @Override
    protected void prepareExtensionSpecificContents() {
        if (chooser.getContext().isClient()) {
            chooser.getConfig().setDefaultClientSupportedDelayCompressionMethods();
            getObject()
                    .setCompressionMethodsClientToServer(
                            chooser.getClientSupportedDelayCompressionMethods(), true);
            getObject()
                    .setCompressionMethodsServerToClient(
                            chooser.getClientSupportedDelayCompressionMethods(), true);
        } else {
            chooser.getConfig().setDefaultServerSupportedDelayCompressionMethods();
            getObject()
                    .setCompressionMethodsClientToServer(
                            chooser.getServerSupportedDelayCompressionMethods(), true);
            getObject()
                    .setCompressionMethodsServerToClient(
                            chooser.getServerSupportedDelayCompressionMethods(), true);
        }
    }
}
