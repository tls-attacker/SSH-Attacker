/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ExitConfirmationMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ExitConfirmationMessageSSHV1Serializier
        extends SshMessageSerializer<ExitConfirmationMessageSSH1> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExitConfirmationMessageSSHV1Serializier(ExitConfirmationMessageSSH1 message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {}
}
