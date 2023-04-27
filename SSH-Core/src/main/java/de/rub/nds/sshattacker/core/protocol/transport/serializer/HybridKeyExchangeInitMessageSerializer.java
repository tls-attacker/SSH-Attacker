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
import de.rub.nds.sshattacker.core.protocol.transport.message.HybridKeyExchangeInitMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class HybridKeyExchangeInitMessageSerializer
        extends SshMessageSerializer<HybridKeyExchangeInitMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private HybridKeyExchangeCombiner combiner;

    public HybridKeyExchangeInitMessageSerializer(
            HybridKeyExchangeInitMessage message, HybridKeyExchangeCombiner combiner) {
        super(message);
        this.combiner = combiner;
    }

    @Override
    public void serializeMessageSpecificContents() {

        int length =
                message.getAgreementPublicKeyLength().getValue()
                        + message.getEncapsulationPublicKeyLength().getValue();
        appendInt(length, DataFormatConstants.STRING_SIZE_LENGTH);

        byte[] keys = new byte[length];
        switch (combiner) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                keys =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getAgreementPublicKey().getValue(),
                                message.getEncapsulationPublicKey().getValue());
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                keys =
                        KeyExchangeUtil.concatenateHybridKeys(
                                message.getEncapsulationPublicKey().getValue(),
                                message.getAgreementPublicKey().getValue());
                break;
            default:
                LOGGER.warn("Unsupported combiner. Could not combine keys, set all bytes to zero.");
        }
        appendBytes(keys);

        LOGGER.debug("HybridKeyLength: " + length);
        LOGGER.debug("HybridKeyBytes: " + ArrayConverter.bytesToHexString(keys));
    }
}
