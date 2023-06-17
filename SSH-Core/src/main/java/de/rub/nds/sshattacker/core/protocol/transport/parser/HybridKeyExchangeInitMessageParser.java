/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.CryptoConstants;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import java.io.InputStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageParser
        extends SshMessageParser<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private HybridKeyExchangeCombiner combiner;
    private int encapsulationSize;
    private int agreementSize;

    /*public HybridKeyExchangeInitMessageParser(
            byte[] array,
            HybridKeyExchangeCombiner combiner,
            int agreementSize,
            int encapsulationSize) {
        super(array);
        this.combiner = combiner;
        this.encapsulationSize = encapsulationSize;
        this.agreementSize = agreementSize;
    }*/

    public HybridKeyExchangeInitMessageParser(SshContext context, InputStream stream) {
        super(stream);
        LOGGER.info(
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
                this.encapsulationSize = CryptoConstants.SNTRUP761_PUBLIC_KEY_SIZE;
                break;
            case CURVE25519_FRODOKEM1344:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.X25519_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.FRODOKEM1344_PUBLIC_KEY_SIZE;
                break;
            case SNTRUP4591761_X25519:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.X25519_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.SNTRUP4591761_PUBLIC_KEY_SIZE;
                break;
            case NISTP521_FIRESABER:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.NISTP521_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.FIRESABER_PUBLIC_KEY_SIZE;
                break;
            case NISTP521_KYBER1024:
                this.combiner = HybridKeyExchangeCombiner.POSTQUANTUM_CONCATENATE_CLASSICAL;
                this.agreementSize = CryptoConstants.NISTP521_POINT_SIZE;
                this.encapsulationSize = CryptoConstants.KYBER1024_PUBLIC_KEY_SIZE;
                break;
        }
        /*        this.combiner = combiner;
        this.encapsulationSize = encapsulationSize;
        this.agreementSize = agreementSize;*/
    }

    /*public HybridKeyExchangeInitMessageParser(
            byte[] array,
            int startPosition,
            HybridKeyExchangeCombiner combiner,
            int agreementSize,
            int encapsulationSize) {
        super(array, startPosition);
        this.combiner = combiner;
        this.encapsulationSize = encapsulationSize;
        this.agreementSize = agreementSize;
    }*/

    private void parseHybridKey(HybridKeyExchangeInitMessage message) {
        int length = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("Total Length: " + length);

        switch (combiner) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                message.setAgreementPublicKeyLength(agreementSize);
                message.setAgreementPublicKey(parseByteArrayField(agreementSize));
                message.setEncapsulationPublicKeyLength(encapsulationSize);
                message.setEncapsulationPublicKey(parseByteArrayField(encapsulationSize));
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                message.setEncapsulationPublicKeyLength(encapsulationSize);
                message.setEncapsulationPublicKey(parseByteArrayField(encapsulationSize));
                message.setAgreementPublicKeyLength(agreementSize);
                message.setAgreementPublicKey(parseByteArrayField(agreementSize));
                break;
            default:
                LOGGER.warn("combiner not supported. Can not update message");
                break;
        }
    }

    @Override
    protected void parseMessageSpecificContents(HybridKeyExchangeInitMessage message) {
        parseHybridKey(message);
    }

    /*  @Override
        protected HybridKeyExchangeInitMessage createMessage() {
            return new HybridKeyExchangeInitMessage();
        }
    */
    @Override
    public void parse(HybridKeyExchangeInitMessage message) {
        parseMessageSpecificContents(message);
    }
}
