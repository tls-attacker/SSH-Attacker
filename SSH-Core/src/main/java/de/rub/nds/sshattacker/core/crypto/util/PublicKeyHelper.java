/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.util;

import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomDsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.parser.DsaPublicKeyParser;
import de.rub.nds.sshattacker.core.crypto.keys.parser.EcdsaPublicKeyParser;
import de.rub.nds.sshattacker.core.crypto.keys.parser.RsaPublicKeyParser;
import de.rub.nds.sshattacker.core.crypto.keys.serializer.DsaPublicKeySerializer;
import de.rub.nds.sshattacker.core.crypto.keys.serializer.EcdsaPublicKeySerializer;
import de.rub.nds.sshattacker.core.crypto.keys.serializer.RsaPublicKeySerializer;
import de.rub.nds.sshattacker.core.exceptions.NotImplementedException;
import java.security.PublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Utility class for public key parsing and serializing */
public final class PublicKeyHelper {

    private static final Logger LOGGER = LogManager.getLogger();

    private PublicKeyHelper() {}

    /**
     * Parses the given encoded public key bytes using the specified key format.
     *
     * @param keyFormat The public key format (must be explicitly known as per RFC 4253 Sec. 6.6)
     * @param encodedPublicKeyBytes Encoded public key in the specified format
     * @return The parsed public key
     * @throws NotImplementedException Thrown whenever support for the specified key format has not
     *     yet been implemented.
     */
    public static SshPublicKey<?, ?> parse(
            PublicKeyFormat keyFormat, byte[] encodedPublicKeyBytes) {
        switch (keyFormat) {
            case SSH_RSA:
                return new RsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
            case SSH_DSS:
                return new DsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
            case ECDSA_SHA2_SECP160K1:
            case ECDSA_SHA2_SECP160R1:
            case ECDSA_SHA2_SECP160R2:
            case ECDSA_SHA2_SECP192K1:
            case ECDSA_SHA2_SECP192R1:
            case ECDSA_SHA2_SECP224K1:
            case ECDSA_SHA2_SECP224R1:
            case ECDSA_SHA2_SECP256K1:
            case ECDSA_SHA2_NISTP256:
            case ECDSA_SHA2_NISTP384:
            case ECDSA_SHA2_NISTP521:
            case ECDSA_SHA2_SECT163K1:
            case ECDSA_SHA2_SECT163R1:
            case ECDSA_SHA2_SECT163R2:
            case ECDSA_SHA2_SECT193R1:
            case ECDSA_SHA2_SECT193R2:
            case ECDSA_SHA2_SECT233K1:
            case ECDSA_SHA2_SECT233R1:
            case ECDSA_SHA2_SECT239K1:
            case ECDSA_SHA2_SECT283K1:
            case ECDSA_SHA2_SECT283R1:
            case ECDSA_SHA2_SECT409K1:
            case ECDSA_SHA2_SECT409R1:
            case ECDSA_SHA2_SECT571K1:
            case ECDSA_SHA2_SECT571R1:
            case ECDSA_SHA2_BRAINPOOL_P256R1:
            case ECDSA_SHA2_BRAINPOOL_P384R1:
            case ECDSA_SHA2_BRAINPOOL_P512R1:
                return new EcdsaPublicKeyParser(encodedPublicKeyBytes, 0).parse();
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
    public static byte[] encode(SshPublicKey<?, ?> hostKey) {
        return encode(hostKey.getPublicKeyFormat(), hostKey.getPublicKey());
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
                    return new RsaPublicKeySerializer((CustomRsaPublicKey) publicKey).serialize();
                case SSH_DSS:
                    return new DsaPublicKeySerializer((CustomDsaPublicKey) publicKey).serialize();
                case ECDSA_SHA2_SECP160K1:
                case ECDSA_SHA2_SECP160R1:
                case ECDSA_SHA2_SECP160R2:
                case ECDSA_SHA2_SECP192K1:
                case ECDSA_SHA2_SECP192R1:
                case ECDSA_SHA2_SECP224K1:
                case ECDSA_SHA2_SECP224R1:
                case ECDSA_SHA2_SECP256K1:
                case ECDSA_SHA2_NISTP256:
                case ECDSA_SHA2_NISTP384:
                case ECDSA_SHA2_NISTP521:
                case ECDSA_SHA2_SECT163K1:
                case ECDSA_SHA2_SECT163R1:
                case ECDSA_SHA2_SECT163R2:
                case ECDSA_SHA2_SECT193R1:
                case ECDSA_SHA2_SECT193R2:
                case ECDSA_SHA2_SECT233K1:
                case ECDSA_SHA2_SECT233R1:
                case ECDSA_SHA2_SECT239K1:
                case ECDSA_SHA2_SECT283K1:
                case ECDSA_SHA2_SECT283R1:
                case ECDSA_SHA2_SECT409K1:
                case ECDSA_SHA2_SECT409R1:
                case ECDSA_SHA2_SECT571K1:
                case ECDSA_SHA2_SECT571R1:
                case ECDSA_SHA2_BRAINPOOL_P256R1:
                case ECDSA_SHA2_BRAINPOOL_P384R1:
                case ECDSA_SHA2_BRAINPOOL_P512R1:
                    return new EcdsaPublicKeySerializer((CustomEcPublicKey) publicKey).serialize();
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
