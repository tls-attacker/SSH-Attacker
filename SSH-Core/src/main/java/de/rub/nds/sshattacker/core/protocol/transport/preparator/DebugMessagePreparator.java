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
import de.rub.nds.sshattacker.core.protocol.transport.message.DebugMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class DebugMessagePreparator extends SshMessagePreparator<DebugMessage> {

    public DebugMessagePreparator() {
        super(MessageIdConstant.SSH_MSG_DEBUG);
    }

    @Override
    public void prepareMessageSpecificContents(DebugMessage object, Chooser chooser) {
        // TODO dummy values for fuzzing
        object.setSoftlyAlwaysDisplay(true);

        object.setSoftlyMessage("", true, chooser.getConfig());
        object.setSoftlyLanguageTag("", true, chooser.getConfig());
    }
}
