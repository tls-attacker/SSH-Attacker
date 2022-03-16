/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.util;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.HostKey;
import de.rub.nds.sshattacker.core.crypto.keys.parser.DsaPublicKeyParser;
import de.rub.nds.sshattacker.core.crypto.keys.parser.RsaPublicKeyParser;
import de.rub.nds.sshattacker.core.crypto.keys.serializer.DsaPublicKeySerializer;
import de.rub.nds.sshattacker.core.crypto.keys.serializer.RsaPublicKeySerializer;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Utility class for public key parsing and serializing */
public final class PublicKeyHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Parses the given encoded public key bytes using the specified key format.
     *
     * @param keyFormat The public key format (must be explicitly known as per RFC 4253 Sec. 6.6)
     * @param encodedPublicKeyBytes Encoded public key in the specified format
     * @return The parsed public key
     * @throws NotImplementedException Thrown whenever support for the specified key format has not
     *     yet been implemented.
     */
    public static PublicKey parse(PublicKeyFormat keyFormat, byte[] encodedPublicKeyBytes) {
        switch (keyFormat) {
            case SSH_RSA:
                return new RsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
            case SSH_DSS:
                return new DsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
            default:
                throw new NotImplementedException(
                        "Parser for public key format " + keyFormat + " is not yet implemented.");
        }
    }

    /**
     * Serializes the given host key using its primary key format into a byte array.
     *
     * @param hostKey Host key to serialize
     * @return A serialized representation of the host key its primary key format
     * @throws NotImplementedException Thrown whenever support for the key format has not yet been
     *     implemented.
     */
    public static byte[] encode(HostKey hostKey) {
        return encode(hostKey.getPublicKeyAlgorithm().getKeyFormat(), hostKey.getPublicKey());
    }

    /**
     * Serializes the given public key using the specified key format into a byte array.
     *
     * @param keyFormat The public key format
     * @param publicKey Public key to serialize
     * @return A serialized representation of the public key in the specified public key format or
     *     null, if key format does not support the given key.
     * @throws NotImplementedException Thrown whenever support for the specified key format has not
     *     yet been implemented.
     */
    public static byte[] encode(PublicKeyFormat keyFormat, PublicKey publicKey) {
        try {
            switch (keyFormat) {
                case SSH_RSA:
                    return new RsaPublicKeySerializer((RSAPublicKey) publicKey).serialize();
                case SSH_DSS:
                    return new DsaPublicKeySerializer((DSAPublicKey) publicKey).serialize();
                default:
                    throw new NotImplementedException(
                            "Serializer for public key format "
                                    + keyFormat
                                    + " is not yet implemented.");
            }
        } catch (ClassCastException e) {
            LOGGER.error(
                    "Unable to encode public key with key format '"
                            + keyFormat
                            + "' due to mismatching classes, got '"
                            + publicKey.getClass().getSimpleName()
                            + "'");
            LOGGER.debug(e);
            return null;
        }
    }
}
