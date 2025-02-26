/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.DelayCompressionExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DelayCompressionExtensionPreparator
        extends AbstractExtensionPreparator<DelayCompressionExtension> {

    public DelayCompressionExtensionPreparator() {
        super(Extension.DELAY_COMPRESSION);
    }

    @Override
    public void prepareExtensionSpecificContents(
            DelayCompressionExtension object, Chooser chooser) {
        Config config = chooser.getConfig();
        if (chooser.getContext().isClient()) {
            object.setCompressionMethodsClientToServer(
                    chooser.getClientSupportedDelayCompressionMethods(), true);
            object.setCompressionMethodsServerToClient(
                    chooser.getClientSupportedDelayCompressionMethods(), true);

        } else {
            object.setCompressionMethodsClientToServer(
                    chooser.getServerSupportedDelayCompressionMethods(), true);
            object.setCompressionMethodsServerToClient(
                    chooser.getServerSupportedDelayCompressionMethods(), true);
        }
        object.setCompressionMethodsLength(object.computeCompressionMethodsLength());
    }
}
