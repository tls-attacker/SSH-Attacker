/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.util;

import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import java.security.PublicKey;

/** Utility class for host key parsing */
public class HostKeyParserFactory {

    /**
     * Creates a parser for a certain host key algorithm
     *
     * @param algorithm The host key algorithm
     * @param hostKeyBytes Encoded host key
     * @return Parser for the given algorithm
     */
    public static Parser<? extends PublicKey> getParserForPublicKeyAuthenticationAlgorithm(
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
