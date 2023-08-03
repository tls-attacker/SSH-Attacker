/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.serializer;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessageSerializer extends SshMessageSerializer<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;

    public ServerPublicKeyMessageSerializer(
            ServerPublicKeyMessage message, HybridKeyExchangeCombiner combiner) {
        super(message);
        this.combiner = combiner;
    }

    @Override
    public void serializeMessageSpecificContents() {
        serializeCookie();
        serializeServerKeyBytes();
        serializeHostKeyBytes();
        // serializeHybridKey();
        // serializeSignature();

    }

    private void serializeCookie() {
        appendBytes(message.getAntiSpoofingCookie().getValue());
        LOGGER.debug(
                "Host key bytes: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getAntiSpoofingCookie().getValue()));
    }

    private void serializeServerKeyBytes() {
        appendInt(
                message.getServerKeyByteLength().getValue(),
                DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key bytes length: " + message.getServerKeyByteLength().getValue());

        appendBytes(message.getServerKeyBytes().getValue());
        LOGGER.debug(
                "Host key bytes: "
                        + ArrayConverter.bytesToRawHexString(
                                message.getServerKeyBytes().getValue()));
    }

    private void serializeHostKeyBytes() {
        appendInt(
                message.getHostKeyByteLenght().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Host key bytes length: " + message.getHostKeyByteLenght().getValue());

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
        LOGGER.debug("Hybrid Key (server): " + combined);
    }
    /*
    private void serializeSignature() {
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendBytes(message.getSignature().getValue());
        LOGGER.debug("Signature: " + message.getSignature());
    }*/

    @Override
    protected byte[] serializeBytes() {
        super.serializeProtocolMessageContents();
        // serializeMessageSpecificContents();
        LOGGER.debug(
                "[bro] SSHV1 serializied PubKey Message. Content: {}",
                ArrayConverter.bytesToHexString(getAlreadySerialized()));
        return getAlreadySerialized();
    }
}
