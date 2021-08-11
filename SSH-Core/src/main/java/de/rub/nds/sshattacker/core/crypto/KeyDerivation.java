/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.Arrays;

public class KeyDerivation {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void deriveKeys(SshContext context) {
        String hashAlgorithm =
                context.getKeyExchangeAlgorithm().orElseThrow(AdjustmentException::new).getDigest();
        KeyExchange keyExchange =
                context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        byte[] exchangeHash = context.getExchangeHashInstance().get();
        byte[] sessionId = context.getSessionID().orElseThrow(AdjustmentException::new);

        context.setInitialIvClientToServer(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        'A',
                        sessionId,
                        context.getCipherAlgorithmClientToServer()
                                .orElseThrow(AdjustmentException::new)
                                .getBlockSize(),
                        hashAlgorithm));
        LOGGER.debug(
                "Key A: "
                        + ArrayConverter.bytesToRawHexString(
                                context.getInitialIvClientToServer().orElse(new byte[0])));
        context.setInitialIvServerToClient(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        'B',
                        sessionId,
                        context.getCipherAlgorithmServerToClient()
                                .orElseThrow(AdjustmentException::new)
                                .getBlockSize(),
                        hashAlgorithm));
        LOGGER.debug(
                "Key B: "
                        + ArrayConverter.bytesToRawHexString(
                                context.getInitialIvServerToClient().orElse(new byte[0])));
        context.setEncryptionKeyClientToServer(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        'C',
                        sessionId,
                        context.getCipherAlgorithmClientToServer()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));
        LOGGER.debug(
                "Key C: "
                        + ArrayConverter.bytesToRawHexString(
                                context.getEncryptionKeyClientToServer().orElse(new byte[0])));
        context.setEncryptionKeyServerToClient(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        'D',
                        sessionId,
                        context.getCipherAlgorithmServerToClient()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));
        LOGGER.debug(
                "Key D: "
                        + ArrayConverter.bytesToRawHexString(
                                context.getEncryptionKeyServerToClient().orElse(new byte[0])));
        context.setIntegrityKeyClientToServer(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        'E',
                        sessionId,
                        context.getMacAlgorithmClientToServer()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));
        LOGGER.debug(
                "Key E: "
                        + ArrayConverter.bytesToRawHexString(
                                context.getIntegrityKeyClientToServer().orElse(new byte[0])));
        context.setIntegrityKeyServerToClient(
                KeyDerivation.deriveKey(
                        keyExchange.getSharedSecret(),
                        exchangeHash,
                        'F',
                        sessionId,
                        context.getMacAlgorithmServerToClient()
                                .orElseThrow(AdjustmentException::new)
                                .getKeySize(),
                        hashAlgorithm));
        LOGGER.debug(
                "Key F: "
                        + ArrayConverter.bytesToRawHexString(
                                context.getIntegrityKeyServerToClient().orElse(new byte[0])));
    }

    static byte[] deriveKey(
            BigInteger sharedSecret,
            byte[] exchangeHash,
            char label,
            byte[] sessionID,
            int outputLen,
            String hashFunction) {
        byte[] serializedSharedSecret = Converter.byteArrayToMpint(sharedSecret.toByteArray());
        try {
            MessageDigest md = MessageDigest.getInstance(hashFunction);
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            outStream.write(
                    md.digest(
                            Arrays.concatenate(
                                    serializedSharedSecret,
                                    exchangeHash,
                                    new byte[] {(byte) label},
                                    sessionID)));

            while (outStream.size() < outputLen) {
                outStream.write(
                        md.digest(
                                Arrays.concatenate(
                                        serializedSharedSecret,
                                        exchangeHash,
                                        outStream.toByteArray())));
            }
            return Arrays.copyOfRange(outStream.toByteArray(), 0, outputLen);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(
                    "Provider does not support this hashFunction:" + e.getMessage());
        } catch (IOException e) {
            LOGGER.error("Error while writing: " + e.getMessage());
            return new byte[0];
        }
    }
}
