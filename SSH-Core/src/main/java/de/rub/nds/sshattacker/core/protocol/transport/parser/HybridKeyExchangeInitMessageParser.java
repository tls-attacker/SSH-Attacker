/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageParser
        extends SshMessageParser<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private final HybridKeyExchangeCombiner combiner;
    private final int encapsulationSize;
    private final int agreementSize;

    public HybridKeyExchangeInitMessageParser(
            byte[] array,
            HybridKeyExchangeCombiner combiner,
            int agreementSize,
            int encapsulationSize) {
        super(array);
        this.combiner = combiner;
        this.encapsulationSize = encapsulationSize;
        this.agreementSize = agreementSize;
    }

    public HybridKeyExchangeInitMessageParser(
            byte[] array,
            int startPosition,
            HybridKeyExchangeCombiner combiner,
            int agreementSize,
            int encapsulationSize) {
        super(array, startPosition);
        this.combiner = combiner;
        this.encapsulationSize = encapsulationSize;
        this.agreementSize = agreementSize;
    }

    private void parseHybridKey() {
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
    protected void parseMessageSpecificContents() {
        parseHybridKey();
    }

    @Override
    protected HybridKeyExchangeInitMessage createMessage() {
        return new HybridKeyExchangeInitMessage();
    }
}
