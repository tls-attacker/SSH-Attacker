/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ClientSessionKeyMessage;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientSessionKeyMessageParser extends SshMessageParser<ClientSessionKeyMessage> {
    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;
    private int agreementSize;
    private int encapsulationSize;

    /*
        public HybridKeyExchangeReplyMessageParser(
                byte[] array,
                int startPosition,
                HybridKeyExchangeCombiner combiner,
                int agreementSize,
                int encapsulationSize) {
            super(array, startPosition);
            this.agreementSize = agreementSize;
            this.encapsulationSize = encapsulationSize;
            this.combiner = combiner;
        }

        public HybridKeyExchangeReplyMessageParser(
                byte[] array,
                HybridKeyExchangeCombiner combiner,
                int agreementSize,
                int encapsulationSize) {
            super(array);
            this.agreementSize = agreementSize;
            this.encapsulationSize = encapsulationSize;
            this.combiner = combiner;
        }
    */

    public ClientSessionKeyMessageParser(SshContext context, InputStream stream) {
        super(stream);

        /*        LOGGER.info(
                "Negotiated Hybrid Key Exchange: "
                        + context.getChooser().getKeyExchangeAlgorithm());
        switch (context.getChooser().getKeyExchangeAlgorithm()) {
            default:
                LOGGER.warn(
                        "Unsupported hybrid key exchange negotiated, treating received HBR_REPLY as sntrup761x25519-sha512@openssh.com");
                // Fallthrough to next case statement intended
            case SNTRUP761_X25519:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.X25519_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.SNTRUP761_CIPHERTEXT_SIZE;
                break;
            case CURVE25519_FRODOKEM1344:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.X25519_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.FRODOKEM1344_CIPHERTEXT_SIZE;
                break;
            case SNTRUP4591761_X25519:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.X25519_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.SNTRUP4591761_CIPHERTEXT_SIZE;
                break;
            case NISTP521_FIRESABER:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.NISTP521_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.FIRESABER_CIPHERTEXT_SIZE;
                break;
            case NISTP521_KYBER1024:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.NISTP521_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.KYBER1024_CIPHERTEXT_SIZE;
                break;
        }*/

        /*        this.agreementSize = agreementSize;
        this.encapsulationSize = encapsulationSize;
        this.combiner = combiner;*/
    }

    private void parseCRC(ClientSessionKeyMessage message) {
        byte[] CRC = parseByteArrayField(4);
        LOGGER.debug("CRC: {}", ArrayConverter.bytesToHexString(CRC));
    }

    private void parseChosenCipherMethod(ClientSessionKeyMessage message) {
        CipherMethod chosenCipherMethod = CipherMethod.fromId(parseIntField(1));
        message.setChosenCipherMethod(chosenCipherMethod);
        LOGGER.debug("Ciphermethod: {}", chosenCipherMethod);
    }

    private void parseAntiSpoofingCookie(ClientSessionKeyMessage message) {
        message.setAntiSpoofingCookie(parseByteArrayField(8));
        LOGGER.debug("AntiSpoofingCookie: {}", message.getAntiSpoofingCookie().getValue());
    }

    private void parseSessionKey(ClientSessionKeyMessage message) {
        // message.setEncryptedSessioKey(parseMultiprecisionAsByteArray());
        message.setEncryptedSessioKey(parseMultiprecision().toByteArray());
        LOGGER.debug(
                "Encrypted Session Key: {}",
                ArrayConverter.bytesToHexString(message.getEncryptedSessioKey().getValue()));
    }

    /*    private void parseHybridKey(ServerPublicKeyMessage message) {
        int length = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("Total Length: " + length);

        switch (combiner) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                message.setPublicKeyLength(agreementSize);
                message.setPublicKey(parseByteArrayField(agreementSize));
                message.setCiphertextLength(encapsulationSize);
                message.setCombinedKeyShare(parseByteArrayField(encapsulationSize));
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                message.setCiphertextLength(encapsulationSize);
                message.setCombinedKeyShare(parseByteArrayField(encapsulationSize));
                message.setPublicKeyLength(agreementSize);
                message.setPublicKey(parseByteArrayField(agreementSize));
                break;
            default:
                LOGGER.warn("combiner not supported. Can not update message");
                break;
        }
    }*/

    /*    private void parseSignature(ServerPublicKeyMessage message) {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: " + message.getSignature());
    }*/

    private void parseProtocolFlags(ClientSessionKeyMessage message) {
        message.setProtocolFlagMask(parseIntField(4));
        LOGGER.debug("Protocol Flags Mask {}", message.getProtocolFlagMask().getValue());

        int flagMask = message.getProtocolFlagMask().getValue();
        String stringProtocolMask = Integer.toBinaryString(flagMask);
        List<ProtocolFlag> chosenProtocolFlags = new ArrayList<>();
        for (int i = 0; i < stringProtocolMask.length(); i++) {
            if (stringProtocolMask.charAt(i) == '1') {
                int id = stringProtocolMask.length() - 1 - i;
                chosenProtocolFlags.add(ProtocolFlag.fromId(id));
                LOGGER.debug("Parsed ProtocolFlags {} at id {}", ProtocolFlag.fromId(id), id);
            }
        }

        message.setChosenProtocolFlags(chosenProtocolFlags);
    }

    @Override
    protected void parseMessageSpecificContents(ClientSessionKeyMessage message) {
        parseChosenCipherMethod(message);
        parseAntiSpoofingCookie(message);
        parseSessionKey(message);
        parseProtocolFlags(message);
        // parseCRC(message);

        // parseHybridKey(message);
        // parseSignature(message);
    }

    /*
        @Override
        protected HybridKeyExchangeReplyMessage createMessage() {
            return new HybridKeyExchangeReplyMessage();
        }
    */

    @Override
    public void parse(ClientSessionKeyMessage message) {
        parseProtocolMessageContents(message);
    }
}
