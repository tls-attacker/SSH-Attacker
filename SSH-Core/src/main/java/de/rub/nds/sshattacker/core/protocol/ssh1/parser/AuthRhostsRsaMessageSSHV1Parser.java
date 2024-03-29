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
import de.rub.nds.sshattacker.core.protocol.ssh1.message.AuthRhostsRsaMessageSSH1;
import java.io.InputStream;
import java.math.BigInteger;

public class AuthRhostsRsaMessageSSHV1Parser extends SshMessageParser<AuthRhostsRsaMessageSSH1> {

    public AuthRhostsRsaMessageSSHV1Parser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseData(AuthRhostsRsaMessageSSH1 message) {

        int usernameLenght = parseIntField(4);
        String username = parseByteString(usernameLenght);
        message.setUsername(username);

        int hostKeyBits = parseIntField(4);
        message.setClientHostKeyBits(hostKeyBits);

        BigInteger hostKeyExponent = parseMultiprecision();
        BigInteger hostKeyModulus = parseMultiprecision();
        message.setHostPublicExponent(ArrayConverter.bigIntegerToByteArray(hostKeyExponent));
        message.setHostPublicModulus(ArrayConverter.bigIntegerToByteArray(hostKeyModulus));
    }

    @Override
    protected void parseMessageSpecificContents(AuthRhostsRsaMessageSSH1 message) {
        parseData(message);
    }

    @Override
    public void parse(AuthRhostsRsaMessageSSH1 message) {
        parseProtocolMessageContents(message);
    }
}
