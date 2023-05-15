/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config;

import de.rub.nds.sshattacker.core.constants.NamedEcGroup;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.XCurveEcPublicKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.util.OpenSSHPrivateKeyUtil;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Set;

/** Utility class for working with SSH keys. */
public final class PubKeyUtil {
    /** Logger instance. */
    private static final Logger LOGGER = LogManager.getLogger();

    /** Private constructor because this is a utility class. */
    private PubKeyUtil() {
        super();
    }

    /** Set of allowed PEM types. */
    private static final Set<String> ALLOWED_PEM_TYPES =
            Set.of("OPENSSH PRIVATE KEY", "RSA PRIVATE KEY");

    /**
     * Parse an SSH private key from the file under the given {@link Path}.
     *
     * @param path OpenSSH PEM file path
     * @return the parsed SSH key
     * @throws IOException if the key data cannot be read
     */
    public static SshPublicKey<?, ?> parsePrivateKey(Path path) throws IOException {
        try (Reader reader = Files.newBufferedReader(path)) {
            return parsePrivateKey(reader);
        }
    }

    /**
     * Parse an SSH private key from the given {@link Reader}.
     *
     * @param reader reader with OpenSSH PEM data
     * @return the parsed SSH key
     * @throws IOException if the key data cannot be read
     */
    public static SshPublicKey<?, ?> parsePrivateKey(Reader reader) throws IOException {
        PemReader pemReader = new PemReader(reader);
        PemObject pem = pemReader.readPemObject();
        if (!ALLOWED_PEM_TYPES.contains(pem.getType())) {
            throw new IOException(String.format("Unexpected PEM file type \"%s\"", pem.getType()));
        }
        return parsePrivateKey(pem.getContent());
    }

    /**
     * Parse an SSH private key from the given PEM content blob.
     *
     * @param blob base64-decoded blob data
     * @return the parsed SSH key
     * @throws IOException if the key data cannot be read
     */
    public static SshPublicKey<?, ?> parsePrivateKey(byte[] blob) throws IOException {
        AsymmetricKeyParameter params = OpenSSHPrivateKeyUtil.parsePrivateKeyBlob(blob);
        if (params instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters rsaParams = (RSAPrivateCrtKeyParameters) params;
            CustomRsaPrivateKey privateKey =
                    new CustomRsaPrivateKey(rsaParams.getExponent(), rsaParams.getModulus());
            CustomRsaPublicKey publicKey =
                    new CustomRsaPublicKey(rsaParams.getPublicExponent(), rsaParams.getModulus());
            LOGGER.debug(
                    "Successfully parsed {} bit RSA keypair", rsaParams.getModulus().bitLength());
            return new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        }

        if (params instanceof Ed25519PrivateKeyParameters) {
            Ed25519PrivateKeyParameters ed25519Params = (Ed25519PrivateKeyParameters) params;
            XCurveEcPrivateKey privateKey =
                    new XCurveEcPrivateKey(ed25519Params.getEncoded(), NamedEcGroup.CURVE25519);
            XCurveEcPublicKey publicKey =
                    new XCurveEcPublicKey(
                            ed25519Params.generatePublicKey().getEncoded(),
                            NamedEcGroup.CURVE25519);
            LOGGER.debug("Successfully parsed ED25519 keypair");
            return new SshPublicKey<>(PublicKeyFormat.SSH_ED25519, publicKey, privateKey);
        }

        throw new IOException("Failed to parse private key: Unsupported format!");
    }
}
