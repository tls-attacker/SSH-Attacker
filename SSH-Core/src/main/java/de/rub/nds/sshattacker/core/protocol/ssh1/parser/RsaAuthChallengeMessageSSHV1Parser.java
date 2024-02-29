/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.RsaAuthChallengeMessageSSH1;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.InputStream;
import java.math.BigInteger;

public class RsaAuthChallengeMessageSSHV1Parser extends SshMessageParser<RsaAuthChallengeMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public RsaAuthChallengeMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageSpecificContents(RsaAuthChallengeMessageSSH1 message) {
        parseEncryptedChallengeModulus(message);
    }

    @Override
    public void parse(RsaAuthChallengeMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }

    private void parseEncryptedChallengeModulus(RsaAuthChallengeMessageSSH1 message) {

        int encryptedChallengeBitLength = parseIntField(4);
        message.setEncryptedChallengeBitLenght(encryptedChallengeBitLength);
        BigInteger modulus = parseMultiprecision();
        message.setIdentityPublicModulus(ArrayConverter.bigIntegerToByteArray(modulus));
    }
}
