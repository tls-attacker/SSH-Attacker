/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;

public class HybridKeyExchangeReplyMessageSerializer
        extends SshMessageSerializer<HybridKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final HybridKeyExchangeCombiner combiner;

    public HybridKeyExchangeReplyMessageSerializer(
            HybridKeyExchangeReplyMessage message, HybridKeyExchangeCombiner combiner) {
        super(message);
        this.combiner = combiner;
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeHostKeyBytes();
        serializeHybridKey();
        serializeSignature();
    }

    private void serializeHostKeyBytes() {
        appendInt(
                message.getHostKeyBytesLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key bytes length: " + message.getHostKeyBytesLength().getValue());

        appendBytes(message.getHostKeyBytes().getValue());
        LOGGER.debug(
                "Host key bytes: "
                        + ArrayConverter.bytesToRawHexString(message.getHostKeyBytes().getValue()));
    }

    private void serializeHybridKey() {
        int length =
                message.getPublicKeyLength().getValue()
                        + message.getCombinedKeyShareLength().getValue();
        appendInt(length, DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Hybrid Key (server) length: " + length);
        byte[] combined;
        switch (combiner) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getPublicKey().getValue(),
                                message.getCombinedKeyShare().getValue());
                appendBytes(combined);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                combined =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getCombinedKeyShare().getValue(),
                                message.getPublicKey().getValue());
                appendBytes(combined);
                break;
            default:
                LOGGER.warn(
                        "The used combiner" + combiner + " is not supported, can not append Bytes");
                combined = new byte[0];
                break;
        }
        LOGGER.debug("Hybrid Key (server): " + Arrays.toString(combined));
    }

    private void serializeSignature() {
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendBytes(message.getSignature().getValue());
        LOGGER.debug("Signature: " + message.getSignature());
    }
}
