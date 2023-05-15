/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

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
            String hashFunction) {
        try {
            MessageDigest md = MessageDigest.getInstance(hashFunction);
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            outStream.write(
                    md.digest(
                            Arrays.concatenate(
                                    sharedSecret,
                                    exchangeHash,
                                    new byte[] {(byte) label},
                                    sessionID)));

            while (outStream.size() < outputLen) {
                outStream.write(
                        md.digest(
                                Arrays.concatenate(
                                        sharedSecret, exchangeHash, outStream.toByteArray())));
            }
            return Arrays.copyOfRange(outStream.toByteArray(), 0, outputLen);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(
                    "Provider does not support this hashFunction:" + e.getMessage());
        } catch (IOException e) {
            LOGGER.error("Error while writing: {}", e.getMessage());
            return new byte[0];
        }
    }
}
