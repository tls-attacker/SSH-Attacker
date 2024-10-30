/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeReplyMessageParser
        extends SshMessageParser<HybridKeyExchangeReplyMessage> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final HybridKeyExchangeCombiner combiner;
    private final int agreementSize;
    private final int encapsulationSize;

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

    private void parseHostKeyBytes() {
        message.setHostKeyBytesLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Host key byte length{}", message.getHostKeyBytesLength());
        message.setHostKeyBytes(parseByteArrayField(message.getHostKeyBytesLength().getValue()));
        LOGGER.debug(
                "Host key bytes: {}",
                () -> ArrayConverter.bytesToHexString(message.getHostKeyBytes().getValue()));
    }

    private void parseHybridKey() {
        int length = parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH);
        LOGGER.debug("Total Length: {}", length);

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
    }

    private void parseSignature() {
        message.setSignatureLength(parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Signature length: {}", message.getSignatureLength().getValue());
        message.setSignature(parseByteArrayField(message.getSignatureLength().getValue()));
        LOGGER.debug("Signature: {}", message.getSignature());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parseHostKeyBytes();
        parseHybridKey();
        parseSignature();
    }

    @Override
    protected HybridKeyExchangeReplyMessage createMessage() {
        return new HybridKeyExchangeReplyMessage();
    }
}
