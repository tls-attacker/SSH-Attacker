/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DelayCompressionExtensionPreparator
        extends AbstractExtensionPreparator<DelayCompressionExtension> {

    public DelayCompressionExtensionPreparator(
            Chooser chooser, DelayCompressionExtension extension) {
        super(chooser, extension, Extension.DELAY_COMPRESSION);
    }

    @Override
    public void prepareExtensionSpecificContents() {
        if (chooser.getContext().isClient()) {
            getObject()
                    .setSoftlyCompressionMethodsClientToServer(
                            chooser.getClientSupportedDelayCompressionMethods(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyCompressionMethodsServerToClient(
                            chooser.getClientSupportedDelayCompressionMethods(),
                            true,
                            chooser.getConfig());

        } else {
            getObject()
                    .setSoftlyCompressionMethodsClientToServer(
                            chooser.getServerSupportedDelayCompressionMethods(),
                            true,
                            chooser.getConfig());
            getObject()
                    .setSoftlyCompressionMethodsServerToClient(
                            chooser.getServerSupportedDelayCompressionMethods(),
                            true,
                            chooser.getConfig());
        }
        getObject()
                .setSoftlyCompressionMethodsLength(
                        getObject().computeCompressionMethodsLength(), chooser.getConfig());
    }
}
