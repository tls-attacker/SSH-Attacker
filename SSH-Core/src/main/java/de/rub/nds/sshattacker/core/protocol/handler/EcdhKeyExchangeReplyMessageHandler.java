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
import de.rub.nds.sshattacker.core.crypto.kex.ECDHKeyExchange;
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
        context.setHostKeyType(message.getHostKeyType().getValue());
        context.setKeyExchangeSignature(message.getSignature().getValue());
        // TODO: Make sure we got an ECDHKeyExchange instance here
        ECDHKeyExchange ecdhKeyExchange = (ECDHKeyExchange) context.getKeyExchangeInstance();
        ecdhKeyExchange.setRemotePublicKey(message.getEphemeralPublicKey().getValue());
        ecdhKeyExchange.computeSharedSecret();

        handleHostKey(message);
        computeExchangeHash();
        KeyDerivation.deriveKeys(context);

        initializeCryptoLayers();
        context.setKeyExchangeComplete(true);
    }

    private void handleHostKey(EcdhKeyExchangeReplyMessage message) {
        // TODO: Implement host key types as enumeration
        // TODO: Improve host key handling in separate class
        if (context.getHostKeyType().equals("ssh-rsa")) {
            handleRsaHostKey(message);
        } else {
            handleEccHostKey(message);
        }
    }

    private void handleEccHostKey(EcdhKeyExchangeReplyMessage message) {
        context.setServerHostKey(message.getHostKeyEcc().getValue());
    }

    private void handleRsaHostKey(EcdhKeyExchangeReplyMessage message) {
        context.setHostKeyRsaExponent(message.getHostKeyRsaExponent().getValue());
        context.setHostKeyRsaModulus(message.getHostKeyRsaModulus().getValue());
        context.appendToExchangeHashInput(ArrayConverter.concatenate(Converter
                .stringToLengthPrefixedBinaryString(context.getHostKeyType()),
                Converter.bytesToLengthPrefixedBinaryString(ArrayConverter.bigIntegerToByteArray(context
                        .getHostKeyRsaExponent())), Converter.bytesToLengthPrefixedBinaryString(ArrayConverter
                        .concatenate(new byte[] { 0x00 }, // asn1 leading byte
                                ArrayConverter.bigIntegerToByteArray(context.getHostKeyRsaModulus())))
        // Converter.bytesToLengthPrefixedBinaryString(ArrayConverter.bigIntegerToByteArray(context.getHostKeyRsaModulus(),
        // 32, false))
                ));
    }

    private void computeExchangeHash() {
        String hashAlgorithm = context.getKeyExchangeAlgorithm().orElseThrow(AdjustmentException::new).getDigest();

        context.appendToExchangeHashInput(context.getKeyExchangeInstance().getLocalKeyPair().serializePublicKey());
        context.appendToExchangeHashInput(context.getKeyExchangeInstance().getRemotePublicKey().serializePublicKey());
        context.appendToExchangeHashInput(Converter.bytesToBytesWithSignByte(context.getKeyExchangeInstance().getSharedSecret()));

        LOGGER.debug("ExchangeHash Input: " + ArrayConverter.bytesToRawHexString(context.getExchangeHashInput()));
        context.setExchangeHash(KeyDerivation.computeExchangeHash(context.getExchangeHashInput(), hashAlgorithm));
        LOGGER.debug("ExchangeHash " + ArrayConverter.bytesToRawHexString(context.getExchangeHash()));
        context.setSessionID(context.getExchangeHash());
    }

    private void initializeCryptoLayers() {
        context.setCryptoLayerClientToServer(CryptoLayerFactory.getCryptoLayer(true, context));
        context.setCryptoLayerServerToClient(CryptoLayerFactory.getCryptoLayer(false, context));
    }
}
