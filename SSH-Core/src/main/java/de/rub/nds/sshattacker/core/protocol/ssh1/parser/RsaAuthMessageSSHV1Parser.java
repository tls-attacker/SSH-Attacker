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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.RsaAuthMessageSSH1;
import java.io.InputStream;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class RsaAuthMessageSSHV1Parser extends SshMessageParser<RsaAuthMessageSSH1> {
    private static final Logger LOGGER = LogManager.getLogger();

    public RsaAuthMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    @Override
    protected void parseMessageSpecificContents(RsaAuthMessageSSH1 message) {
        parseIdentityPublicModulus(message);
    }

    @Override
    public void parse(RsaAuthMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }

    private void parseIdentityPublicModulus(RsaAuthMessageSSH1 message) {

        int identityModulusBitLength = parseIntField(4);
        message.setIdentityPublicModulusBitLenght(identityModulusBitLength);
        BigInteger modulus = parseMultiprecision();
        message.setIdentityPublicModulus(ArrayConverter.bigIntegerToByteArray(modulus));
    }
}
