/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.serializer;

import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.message.RsaAuthChallengeMessageSSH1;

public class RsaAuthChallengeMessageSSHV1Serializier
        extends Ssh1MessageSerializer<RsaAuthChallengeMessageSSH1> {

    public RsaAuthChallengeMessageSSHV1Serializier(RsaAuthChallengeMessageSSH1 message) {
        super(message);
    }

    @Override
    public void serializeMessageSpecificContents() {}
}
