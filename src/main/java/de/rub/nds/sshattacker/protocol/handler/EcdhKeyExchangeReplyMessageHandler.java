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

public class EcdhKeyExchangeReplyMessageHandler extends Handler<EcdhKeyExchangeReplyMessage> {

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
        adjustKeys();
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
        context.setInitialIvServerToClient(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'B', context.getSessionID(), context.getCipherAlgorithmServerToClient().getBlockSize(), hashAlgorithm));
        context.setEncryptionKeyClientToServer(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'C', context.getSessionID(), context.getCipherAlgorithmClientToServer().getKeySize(), hashAlgorithm));
        context.setEncryptionKeyServerToClient(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'D', context.getSessionID(), context.getCipherAlgorithmServerToClient().getKeySize(), hashAlgorithm));
        context.setIntegrityKeyClientToServer(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'E', context.getSessionID(), context.getMacAlgorithmClientToServer().getKeySize(), hashAlgorithm));
        context.setIntegrityKeyServerToClient(KeyDerivation.deriveKey(context.getSharedSecret(), context.getExchangeHash(), (byte) 'A', context.getSessionID(), context.getMacAlgorithmServerToClient().getKeySize(), hashAlgorithm));
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
        context.setExchangeHash(KeyDerivation.computeExchangeHash(context.getExchangeHashInput(), hashAlgorithm));
    }

    private void computeSharedSecret() {
        // skip asn1 byte

        EllipticCurve curve = CurveFactory.getCurve(NamedGroup.SECP256R1);
        BigInteger serverX = new BigInteger(1, Arrays.copyOfRange(context.getServerEcdhPublicKey(), 1, 33));
        BigInteger serverY = new BigInteger(1, Arrays.copyOfRange(context.getServerEcdhPublicKey(), 33, 65));

        Point serverPoint = curve.getPoint(serverX, serverY);
        Point sharedPoint = curve.mult(new BigInteger(1, context.getClientEcdhSecretKey()), serverPoint);
        context.setSharedSecret(sharedPoint.getX().getData().toByteArray());

    }
}
