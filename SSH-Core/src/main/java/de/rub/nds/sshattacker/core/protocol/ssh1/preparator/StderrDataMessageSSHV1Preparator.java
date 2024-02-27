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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.StderrDataMessageSSH1;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class StderrDataMessageSSHV1Preparator extends SshMessagePreparator<StderrDataMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;

    public StderrDataMessageSSHV1Preparator(Chooser chooser, StderrDataMessageSSH1 message) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_STDERR_DATA);
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        if (getObject().getData() == null) {
            getObject().setData("DummyValue");
        }
        LOGGER.debug(getObject().getData().getValue());
    }
}
