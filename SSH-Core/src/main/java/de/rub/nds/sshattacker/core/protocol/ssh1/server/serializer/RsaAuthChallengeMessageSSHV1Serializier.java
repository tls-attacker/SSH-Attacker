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
import java.math.BigInteger;

public class RsaAuthChallengeMessageSSHV1Serializier
        extends Ssh1MessageSerializer<RsaAuthChallengeMessageSSH1> {

    public RsaAuthChallengeMessageSSHV1Serializier(RsaAuthChallengeMessageSSH1 message) {
        super(message);
    }

    private void serializeEncryptedChallenge() {
        appendMultiPrecision(new BigInteger(1, message.getEncryptedChallenge().getValue()));
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeEncryptedChallenge();
    }
}
