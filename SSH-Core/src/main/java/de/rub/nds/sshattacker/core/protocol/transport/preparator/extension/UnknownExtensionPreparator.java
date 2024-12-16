/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.protocol.transport.message.extension.UnknownExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UnknownExtensionPreparator extends AbstractExtensionPreparator<UnknownExtension> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UnknownExtensionPreparator(Chooser chooser, UnknownExtension extension) {
        super(chooser, extension);
    }

    @Override
    public void prepareExtensionSpecificContents() {
        getObject().setName("hello-from@ssh-attacker.de", true);
        getObject().setValue(new byte[100], true);
    }
}
