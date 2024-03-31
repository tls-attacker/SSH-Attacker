/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.FailureMessageSSH1;

public class FailureMessageSerializier extends Ssh1MessageSerializer<FailureMessageSSH1> {

    public FailureMessageSerializier(FailureMessageSSH1 message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {}
}
