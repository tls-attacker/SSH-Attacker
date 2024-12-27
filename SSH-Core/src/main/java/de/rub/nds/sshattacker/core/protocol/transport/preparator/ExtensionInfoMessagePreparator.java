/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class ExtensionInfoMessagePreparator extends SshMessagePreparator<ExtensionInfoMessage> {

    public ExtensionInfoMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_EXT_INFO);
    }

    @Override
    public void prepareMessageSpecificContents(ExtensionInfoMessage object, Chooser chooser) {
        if (chooser.getContext().isClient()) {
            object.setExtensions(chooser.getClientSupportedExtensions(), true);
        } else {
            object.setExtensions(chooser.getServerSupportedExtensions(), true);
        }

        object.getExtensions().forEach(extension -> extension.prepare(chooser));
    }
}
