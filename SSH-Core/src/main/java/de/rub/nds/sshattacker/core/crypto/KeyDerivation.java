/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.util.Converter;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.math.ec.rfc7748.X25519;
import org.bouncycastle.util.Arrays;

public class KeyDerivation {

    private static final Logger LOGGER = LogManager.getLogger();

    public static byte[] DheX25519(byte[] secretKey, byte[] publicKey) {
        byte[] sharedKey = new byte[CryptoConstants.X25519_POINT_SIZE];
        X25519.precompute();
        X25519.scalarMult(secretKey, 0, publicKey, 0, sharedKey, 0);
        return sharedKey;
    }

    public static byte[] computeExchangeHash(byte[] input, String hashAlgorithm) {
        return getMessageDigestInstance(hashAlgorithm).digest(input);
    }

    public static byte[] computeExchangeHash(String clientVersion, String serverVersion, byte[] clientInitMessage,
            byte[] serverInitMessage, byte[] hostKey, byte[] clientKeyShare, byte[] serverKeyShare,
            byte[] sharedSecret, String hashFunction) {
        byte[] clientVersionConverted = Converter.stringToLengthPrefixedBinaryString(clientVersion);
        byte[] serverVersionConverted = Converter.stringToLengthPrefixedBinaryString(serverVersion);
        byte[] clientInitMessageString = Converter.bytesToLengthPrefixedBinaryString(clientInitMessage);
        byte[] serverInitMessageString = Converter.bytesToLengthPrefixedBinaryString(serverInitMessage);
        byte[] hostKeyString = Converter.bytesToLengthPrefixedBinaryString(hostKey);
        byte[] clientKeyShareString = Converter.bytesToLengthPrefixedBinaryString(clientKeyShare);
        byte[] serverKeyShareString = Converter.bytesToLengthPrefixedBinaryString(serverKeyShare);
        byte[] keyShareString = Converter.byteArrayToMpint(sharedSecret);
        byte[] input = ArrayConverter.concatenate(clientVersionConverted, serverVersionConverted,
                clientInitMessageString, serverInitMessageString, hostKeyString, clientKeyShareString,
                serverKeyShareString, keyShareString);

        return getMessageDigestInstance(hashFunction).digest(input);
    }

    public static MessageDigest getMessageDigestInstance(String hashFunction) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(hashFunction);

        } catch (NoSuchAlgorithmException e) {
            if (hashFunction.equals("")) {
                hashFunction = "empty";
            }
            LOGGER.error("Provider does not support this hashFunction:" + hashFunction + e.getMessage());
        }
        return md;
    }

    public static void deriveKeys(SshContext context) {
        String hashAlgorithm = context.getKeyExchangeAlgorithm().orElseThrow(AdjustmentException::new).getDigest();
        KeyExchange keyExchange = context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        byte[] exchangeHash = context.getExchangeHash().orElseThrow(AdjustmentException::new);
        byte[] sessionId = context.getSessionID().orElseThrow(AdjustmentException::new);

        context.setInitialIvClientToServer(KeyDerivation.deriveKey(keyExchange.getSharedSecret(),
                exchangeHash, (byte) 'A', sessionId, context
                        .getCipherAlgorithmClientToServer().orElseThrow(AdjustmentException::new).getBlockSize(), hashAlgorithm));
        LOGGER.debug("Key A: " + ArrayConverter.bytesToRawHexString(context.getInitialIvClientToServer().orElse(new byte[0])));
        context.setInitialIvServerToClient(KeyDerivation.deriveKey(keyExchange.getSharedSecret(),
                exchangeHash, (byte) 'B', sessionId, context
                        .getCipherAlgorithmServerToClient().orElseThrow(AdjustmentException::new).getBlockSize(), hashAlgorithm));
        LOGGER.debug("Key B: " + ArrayConverter.bytesToRawHexString(context.getInitialIvServerToClient().orElse(new byte[0])));
        context.setEncryptionKeyClientToServer(KeyDerivation.deriveKey(keyExchange.getSharedSecret(), exchangeHash, (byte) 'C', sessionId, context.getCipherAlgorithmClientToServer()
                .orElseThrow(AdjustmentException::new).getKeySize(), hashAlgorithm));
        LOGGER.debug("Key C: " + ArrayConverter.bytesToRawHexString(context.getEncryptionKeyClientToServer().orElse(new byte[0])));
        context.setEncryptionKeyServerToClient(KeyDerivation.deriveKey(keyExchange.getSharedSecret(), exchangeHash, (byte) 'D', sessionId, context.getCipherAlgorithmServerToClient()
                .orElseThrow(AdjustmentException::new).getKeySize(), hashAlgorithm));
        LOGGER.debug("Key D: " + ArrayConverter.bytesToRawHexString(context.getEncryptionKeyServerToClient().orElse(new byte[0])));
        context.setIntegrityKeyClientToServer(KeyDerivation.deriveKey(keyExchange.getSharedSecret(), exchangeHash, (byte) 'E', sessionId, context.getMacAlgorithmClientToServer()
                .orElseThrow(AdjustmentException::new).getKeySize(), hashAlgorithm));
        LOGGER.debug("Key E: " + ArrayConverter.bytesToRawHexString(context.getIntegrityKeyClientToServer().orElse(new byte[0])));
        context.setIntegrityKeyServerToClient(KeyDerivation.deriveKey(keyExchange.getSharedSecret(), exchangeHash, (byte) 'F', sessionId, context.getMacAlgorithmServerToClient()
                .orElseThrow(AdjustmentException::new).getKeySize(), hashAlgorithm));
        LOGGER.debug("Key F: " + ArrayConverter.bytesToRawHexString(context.getIntegrityKeyServerToClient().orElse(new byte[0])));
    }

    static byte[] deriveKey(byte[] sharedKey, byte[] exchangeHash, byte use, byte[] sessionID, int outputLen,
            String hashFunction) {
        byte[] sharedKeyMpint = Converter.byteArrayToMpint(sharedKey);
        try {
            MessageDigest md = MessageDigest.getInstance(hashFunction);
            ByteArrayOutputStream outStream = new ByteArrayOutputStream();

            outStream.write(md.digest(Arrays.concatenate(sharedKeyMpint, exchangeHash, new byte[] { use }, sessionID)));

            while (outStream.size() < outputLen) {
                outStream.write(md.digest(Arrays.concatenate(sharedKeyMpint, exchangeHash, outStream.toByteArray())));
            }
            return Arrays.copyOfRange(outStream.toByteArray(), 0, outputLen);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Provider does not support this hashFunction:" + e.getMessage());
        } catch (IOException e) {
            LOGGER.error("Error while writing: " + e.getMessage());
            return new byte[0];
        }
    }
}
