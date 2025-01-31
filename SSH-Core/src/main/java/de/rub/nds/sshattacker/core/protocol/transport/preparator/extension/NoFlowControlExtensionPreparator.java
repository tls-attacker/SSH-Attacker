/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator.extension;

import de.rub.nds.sshattacker.core.constants.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.message.extension.NoFlowControlExtension;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NoFlowControlExtensionPreparator extends AbstractExtensionPreparator<NoFlowControlExtension> {

    public NoFlowControlExtensionPreparator() {
        super(Extension.NO_FLOW_CONTROL);
    }

    @Override
    public void prepareExtensionSpecificContents(NoFlowControlExtension object, Chooser chooser) {
        object.setSoftlyChoice("p", true, chooser.getConfig());
    }
}
