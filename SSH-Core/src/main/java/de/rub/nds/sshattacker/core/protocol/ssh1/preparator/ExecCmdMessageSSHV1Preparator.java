/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.DebugMessageSSH1;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ExecCmdMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExecCmdMessageSSHV1Preparator extends SshMessagePreparator<ExecCmdMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;

    public ExecCmdMessageSSHV1Preparator(Chooser chooser, ExecCmdMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_CMSG_EXEC_CMD);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getCommand() == null) {
            getObject().setCommand("DummyValue");
        }
        LOGGER.debug(getObject().getCommand().getValue());
    }
}
