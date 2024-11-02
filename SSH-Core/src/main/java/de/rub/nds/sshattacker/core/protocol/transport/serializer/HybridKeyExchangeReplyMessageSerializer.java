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
import java.util.Arrays;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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
    protected void serializeMessageSpecificContents() {
        serializeHostKeyBytes();
        serializeHybridKey();
        serializeSignature();
    }

    private void serializeHostKeyBytes() {
        Integer hostKeyBytesLength = message.getHostKeyBytesLength().getValue();
        LOGGER.debug("Host key bytes length: {}", hostKeyBytesLength);
        appendInt(hostKeyBytesLength, DataFormatConstants.STRING_SIZE_LENGTH);

        byte[] hostKeyBytes = message.getHostKeyBytes().getValue();
        LOGGER.debug("Host key bytes: {}", () -> ArrayConverter.bytesToRawHexString(hostKeyBytes));
        appendBytes(hostKeyBytes);
    }

    private void serializeHybridKey() {
        int length =
                message.getPublicKeyLength().getValue()
                        + message.getCombinedKeyShareLength().getValue();
        appendInt(length, DataFormatConstants.MPINT_SIZE_LENGTH);
        LOGGER.debug("Hybrid Key (server) length: {}", length);
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
                LOGGER.warn("The used combiner{} is not supported, can not append Bytes", combiner);
                combined = new byte[0];
                break;
        }
        LOGGER.debug("Hybrid Key (server): {}", Arrays.toString(combined));
    }

    private void serializeSignature() {
        Integer signatureLength = message.getSignatureLength().getValue();
        LOGGER.debug("Signature length: {}", signatureLength);
        appendInt(signatureLength, DataFormatConstants.STRING_SIZE_LENGTH);
        appendBytes(message.getSignature().getValue());
        LOGGER.debug("Signature: {}", message.getSignature());
    }
}
