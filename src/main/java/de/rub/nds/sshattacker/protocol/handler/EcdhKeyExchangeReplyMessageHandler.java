package de.rub.nds.sshattacker.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.crypto.KeyDerivation;
import de.rub.nds.sshattacker.imported.ec_.CurveFactory;
import de.rub.nds.sshattacker.imported.ec_.EllipticCurve;
import de.rub.nds.sshattacker.imported.ec_.NamedGroup;
import de.rub.nds.sshattacker.imported.ec_.Point;
import de.rub.nds.sshattacker.protocol.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.state.SshContext;
import de.rub.nds.sshattacker.util.Converter;
import java.math.BigInteger;
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageHandler extends Handler<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    
    public EcdhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(EcdhKeyExchangeReplyMessage message) {
        context.setHostKeyType(message.getHostKeyType().getValue());
        context.setServerEcdhPublicKey(message.getEphemeralPublicKey().getValue());
        context.setKeyExchangeSignature(message.getSignature().getValue());
        if (context.getHostKeyType().equals("ssh-rsa")) { // TODO refine logic
            handleRsaHostKey(message);
        } else {
            handleEccHostKey(message);
        }

        adjustExchangeHash();
        context.setSessionID(context.getExchangeHash());
        adjustKeys();
        context.getCryptoLayer().init();
    }

    private void handleEccHostKey(EcdhKeyExchangeReplyMessage message) {
        context.setServerHostKey(message.getHostKeyEcc().getValue());
    }

    private void handleRsaHostKey(EcdhKeyExchangeReplyMessage message) {
        context.setHostKeyRsaExponent(message.getHostKeyRsaExponent().getValue());
        context.setHostKeyRsaModulus(message.getHostKeyRsaModulus().getValue());
        context.appendToExchangeHashInput(
                ArrayConverter.concatenate(
                        Converter.stringToLengthPrefixedString(context.getHostKeyType()),
                        Converter.bytesToLenghPrefixedString(ArrayConverter.bigIntegerToByteArray(context.getHostKeyRsaExponent())),
                        Converter.bytesToLenghPrefixedString(ArrayConverter.concatenate(new byte[]{00}, // asn1 leading byte
                        ArrayConverter.bigIntegerToByteArray(context.getHostKeyRsaModulus())))
                //                        Converter.bytesToLenghPrefixedString(ArrayConverter.bigIntegerToByteArray(context.getHostKeyRsaModulus(), 32, false))
                ));
    }

    private void adjustKeys() {
        // hashalgorithm is the same used in the key exchange

        // TODO not clean, works for now
        String hashAlgorithm = "";
        if (context.getKeyExchangeAlgorithm().toString().contains("256")) {
            hashAlgorithm = "SHA-256";
        } else if (context.getKeyExchangeAlgorithm().toString().contains("384")) {
            hashAlgorithm = "SHA-384";
        } else if (context.getKeyExchangeAlgorithm().toString().contains("512")) {
            hashAlgorithm = "SHA-512";
        } else if (context.getKeyExchangeAlgorithm().toString().contains("sha1")) {
            hashAlgorithm = "SHA-1";
        }

        context.setInitialIvClientToServer(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'A', context.getSessionID(), context.getCipherAlgorithmClientToServer().getBlockSize(), hashAlgorithm));
        LOGGER.debug("Key A: " + ArrayConverter.bytesToRawHexString(context.getInitialIvClientToServer()));
        context.setInitialIvServerToClient(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'B', context.getSessionID(), context.getCipherAlgorithmServerToClient().getBlockSize(), hashAlgorithm));
        LOGGER.debug("Key B: " + ArrayConverter.bytesToRawHexString(context.getInitialIvServerToClient()));
        context.setEncryptionKeyClientToServer(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'C', context.getSessionID(), context.getCipherAlgorithmClientToServer().getKeySize(), hashAlgorithm));
        LOGGER.debug("Key C: " + ArrayConverter.bytesToRawHexString(context.getEncryptionKeyClientToServer()));
        context.setEncryptionKeyServerToClient(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'D', context.getSessionID(), context.getCipherAlgorithmServerToClient().getKeySize(), hashAlgorithm));
        LOGGER.debug("Key D: " + ArrayConverter.bytesToRawHexString(context.getEncryptionKeyServerToClient()));
        context.setIntegrityKeyClientToServer(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'E', context.getSessionID(), context.getMacAlgorithmClientToServer().getKeySize(), hashAlgorithm));
        LOGGER.debug("Key E: " + ArrayConverter.bytesToRawHexString(context.getIntegrityKeyClientToServer()));
        context.setIntegrityKeyServerToClient(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'A', context.getSessionID(), context.getMacAlgorithmServerToClient().getKeySize(), hashAlgorithm));
        LOGGER.debug("Key F: " + ArrayConverter.bytesToRawHexString(context.getIntegrityKeyServerToClient()));

    }

    private void adjustExchangeHash() {
        // TODO not clean, works for now
        String hashAlgorithm = "";
        if (context.getKeyExchangeAlgorithm().toString().contains("256")) {
            hashAlgorithm = "SHA-256";
        } else if (context.getKeyExchangeAlgorithm().toString().contains("384")) {
            hashAlgorithm = "SHA-384";
        } else if (context.getKeyExchangeAlgorithm().toString().contains("512")) {
            hashAlgorithm = "SHA-512";
        } else if (context.getKeyExchangeAlgorithm().toString().contains("sha1")) {
            hashAlgorithm = "SHA-1";
        }

        context.appendToExchangeHashInput(context.getClientEcdhPublicKey());
        context.appendToExchangeHashInput(context.getServerEcdhPublicKey());
        computeSharedSecret();

        // TODO apply ASN1 sign coding to all bignums
        context.appendToExchangeHashInput(Converter.bytesToBytesWithSignByte(context.getSharedSecret()));
        LOGGER.debug("ExchangeHash Input: " + ArrayConverter.bytesToRawHexString(context.getExchangeHashInput()));
        context.setExchangeHash(KeyDerivation.computeExchangeHash(context.getExchangeHashInput(), hashAlgorithm));
        LOGGER.debug("ExchangeHash " + ArrayConverter.bytesToRawHexString(context.getExchangeHash()));
    }

    private void computeSharedSecret() {
        byte[] sharedSecret = KeyDerivation.DheNistP256(context.getClientEcdhSecretKey(), context.getServerEcdhPublicKey());
        context.setSharedSecret(sharedSecret);
        LOGGER.debug("SharedSecret: " + ArrayConverter.bytesToRawHexString(context.getSharedSecret()));
    }
}
