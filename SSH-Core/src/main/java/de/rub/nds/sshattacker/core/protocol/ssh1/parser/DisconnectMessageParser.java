/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.DisconnectMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DisconnectMessageParser extends SshMessageParser<DisconnectMessage> {
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

    public DisconnectMessageParser(SshContext context, InputStream stream) {
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

    private void parseCRC(DisconnectMessage message) {
        byte[] CRC = parseByteArrayField(4);
        LOGGER.debug("CRC: {}", ArrayConverter.bytesToHexString(CRC));
    }

    private void parseDisconnectReason(DisconnectMessage message) {
        int lenght = parseIntField(4);
        String disconnectReason = parseByteString(lenght);
        message.setDisconnectReason(disconnectReason);
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

    private void parseProtocolFlags(DisconnectMessage message) {}

    @Override
    protected void parseMessageSpecificContents(DisconnectMessage message) {
        parseDisconnectReason(message);
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
    public void parse(DisconnectMessage message) {
        parseProtocolMessageContents(message);
    }
}
