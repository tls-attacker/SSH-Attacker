/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.handler;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.PublicKeyAuthenticationAlgorithm;
import de.rub.nds.sshattacker.core.crypto.kex.ECDHKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.protocol.layers.CryptoLayerFactory;
import de.rub.nds.sshattacker.core.protocol.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import de.rub.nds.sshattacker.core.crypto.KeyDerivation;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class EcdhKeyExchangeReplyMessageHandler extends Handler<EcdhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public EcdhKeyExchangeReplyMessageHandler(SshContext context) {
        super(context);
    }

    @Override
    public void handle(EcdhKeyExchangeReplyMessage message) {
        context.setHostKeyType(PublicKeyAuthenticationAlgorithm.fromName(message.getHostKeyType().getValue()));
        context.setKeyExchangeSignature(message.getSignature().getValue());
        // TODO: Make sure we got an ECDHKeyExchange instance here
        ECDHKeyExchange ecdhKeyExchange = (ECDHKeyExchange) context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);
        ecdhKeyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        ecdhKeyExchange.computeSharedSecret();

        handleHostKey(message);
        computeExchangeHash();
        KeyDerivation.deriveKeys(context);

        initializeCryptoLayers();
    }

    private void handleHostKey(EcdhKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        if (context.getHostKeyType().orElseThrow(AdjustmentException::new) == PublicKeyAuthenticationAlgorithm.SSH_RSA) {
            handleRsaHostKey(message);
        } else {
            LOGGER.fatal("Unable to handle host key, unsupported host key algorithm: " + context.getHostKeyType().toString());
            throw new AdjustmentException("Unsupported host key algorithm");
        }
    }

    private void handleRsaHostKey(EcdhKeyExchangeReplyMessage message) {
        context.appendToExchangeHashInput(ArrayConverter.concatenate(Converter
                .stringToLengthPrefixedBinaryString(context.getHostKeyType().orElseThrow(AdjustmentException::new).toString()), Converter
                .bytesToLengthPrefixedBinaryString(ArrayConverter.bigIntegerToByteArray(message.getHostKeyRsaExponent()
                        .getValue())), Converter.bytesToLengthPrefixedBinaryString(ArrayConverter.concatenate(
                new byte[] { 0x00 }, // asn1 leading byte
                ArrayConverter.bigIntegerToByteArray(message.getHostKeyRsaModulus().getValue())))));
    }

    private void computeExchangeHash() {
        String hashAlgorithm = context.getKeyExchangeAlgorithm().orElseThrow(AdjustmentException::new).getDigest();
        KeyExchange keyExchange = context.getKeyExchangeInstance().orElseThrow(AdjustmentException::new);

        context.appendToExchangeHashInput(keyExchange.getLocalKeyPair().serializePublicKey());
        context.appendToExchangeHashInput(keyExchange.getRemotePublicKey().serializePublicKey());
        context.appendToExchangeHashInput(Converter.bytesToBytesWithSignByte(keyExchange.getSharedSecret()));

        LOGGER.debug("ExchangeHash Input: " + ArrayConverter.bytesToRawHexString(context.getExchangeHashInput()));
        byte[] exchangeHash = KeyDerivation.computeExchangeHash(context.getExchangeHashInput(), hashAlgorithm);
        context.setExchangeHash(exchangeHash);
        LOGGER.debug("ExchangeHash " + ArrayConverter.bytesToRawHexString(exchangeHash));
        if(!context.getSessionID().isPresent()) {
            context.setSessionID(exchangeHash);
        }
    }

    private void initializeCryptoLayers() {
        context.setCryptoLayerClientToServer(CryptoLayerFactory.getCryptoLayer(true, context));
        context.setCryptoLayerServerToClient(CryptoLayerFactory.getCryptoLayer(false, context));
    }
}
