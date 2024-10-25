/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.RsaAuthMessageSSH1;
import java.io.InputStream;
import java.math.BigInteger;

public class RsaAuthMessageSSHV1Parser extends Ssh1MessageParser<RsaAuthMessageSSH1> {

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
