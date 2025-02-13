/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto;

import de.rub.nds.sshattacker.core.constants.HashFunction;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

public final class KeyDerivation {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeyDerivation() {
        super();
    }

    public static byte[] deriveKey(
            byte[] sharedSecret,
            byte[] exchangeHash,
            char label,
            byte[] sessionID,
            int outputLen,
            HashFunction hashFunction) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashFunction.getJavaName());
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();
            md.update(sharedSecret);
            md.update(exchangeHash);
            md.update((byte) label);
            md.update(sessionID);
            outStream.write(md.digest());
            while (outStream.size() < outputLen) {
                md.update(sharedSecret);
                md.update(exchangeHash);
                md.update(outStream.toByteArray());
                outStream.write(md.digest());
            }
            return Arrays.copyOfRange(outStream.toByteArray(), 0, outputLen);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(
                    "Provider does not support this hash function:" + e.getMessage());
        } catch (IOException e) {
            LOGGER.error("Error while writing: {}", e.getMessage());
            return new byte[0];
        }
    }
}
