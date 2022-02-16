/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.util;

import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.security.PublicKey;

public class HostKeyParserFactory {

    public static Parser<? extends PublicKey> getParserForHostKeyAlgorithm(
            PublicKeyAuthenticationAlgorithm algorithm, byte[] hostKeyBytes) {
        switch (algorithm) {
            case SSH_RSA:
            case RSA_SHA2_256:
            case RSA_SHA2_512:
                return new RsaPublicKeyParser(hostKeyBytes, 0);
            default:
                throw new NotImplementedException(
                        "Parser for host key algorithm " + algorithm + " is not yet implemented.");
        }
    }
}
