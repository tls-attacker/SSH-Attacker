/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.constants.SignatureEncoding;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.DhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.signature.SigningSignature;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.MissingExchangeHashInputException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.DhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class DhKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<DhKeyExchangeReplyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public DhKeyExchangeReplyMessagePreparator(Chooser chooser, DhKeyExchangeReplyMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEXDH_REPLY);
        prepareHostKey();
        prepareEphemeralPublicKey();
        updateExchangeHashWithSharedSecret();
        computeExchangeHash();
        prepareSignature();
        setSessionId();
    }

    private void prepareHostKey() {
        SshPublicKey<?, ?> serverHostKey = chooser.getNegotiatedServerHostKey();
        chooser.getContext().setServerHostKey(serverHostKey);
        chooser.getContext().getExchangeHashInputHolder().setServerHostKey(serverHostKey);
        getObject().setHostKey(PublicKeyHelper.encode(serverHostKey), true);
    }

    private void prepareEphemeralPublicKey() {
        DhKeyExchange keyExchange = chooser.getDhKeyExchange();
        keyExchange.generateLocalKeyPair();
        getObject().setEphemeralPublicKey(keyExchange.getLocalKeyPair().getPublic().getY(), true);
        // Compute shared secret if remote public key is available
        if (keyExchange.getRemotePublicKey() != null) {
            keyExchange.computeSharedSecret();
            chooser.getContext().setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn(
                    "Unable to compute shared secret in DH key exchange reply message, no remote public key is present");
        }
        // Update exchange hash with local public key
        chooser.getContext()
                .getExchangeHashInputHolder()
                .setDhServerPublicKey(keyExchange.getLocalKeyPair().getPublic().getY());
    }

    private void updateExchangeHashWithSharedSecret() {
        DhKeyExchange keyExchange = chooser.getDhKeyExchange();
        if (keyExchange.isComplete()) {
            chooser.getContext()
                    .getExchangeHashInputHolder()
                    .setSharedSecret(keyExchange.getSharedSecret());
        } else {
            LOGGER.warn(
                    "Unable to set shared secret in exchange hash, key exchange is still ongoing");
        }
    }

    private void computeExchangeHash() {
        try {
            chooser.getContext()
                    .setExchangeHash(
                            ExchangeHash.computeDhHash(
                                    chooser.getKeyExchangeAlgorithm(),
                                    chooser.getContext().getExchangeHashInputHolder()));
        } catch (MissingExchangeHashInputException e) {
            LOGGER.warn(
                    "Failed to compute exchange hash and update context, some inputs for exchange hash computation are missing");
            LOGGER.debug(e);
        } catch (CryptoException e) {
            LOGGER.error(
                    "Unexpected cryptographic exception occurred during exchange hash computation");
            LOGGER.debug(e);
        }
    }

    private void prepareSignature() {
        SshPublicKey<?, ?> serverHostKey = chooser.getNegotiatedServerHostKey();
        Optional<byte[]> exchangeHash = chooser.getContext().getExchangeHash();
        SigningSignature signingSignature;
        try {
            signingSignature =
                    SignatureFactory.getSigningSignature(
                            chooser.getServerHostKeyAlgorithm(), serverHostKey);
            SignatureEncoding signatureEncoding =
                    chooser.getServerHostKeyAlgorithm().getSignatureEncoding();
            ByteArrayOutputStream signatureOutput = new ByteArrayOutputStream();
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            signatureEncoding.getName().length(),
                            DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(signatureEncoding.getName().getBytes(StandardCharsets.US_ASCII));
            byte[] rawSignature = signingSignature.sign(exchangeHash.orElse(new byte[0]));
            signatureOutput.write(
                    ArrayConverter.intToBytes(
                            rawSignature.length, DataFormatConstants.STRING_SIZE_LENGTH));
            signatureOutput.write(rawSignature);
            getObject().setSignature(signatureOutput.toByteArray(), true);
        } catch (CryptoException e) {
            LOGGER.error(
                    "An unexpected cryptographic exception occurred during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            getObject().setSignature(new byte[0], true);
        } catch (IOException e) {
            LOGGER.error(
                    "An unexpected IOException occured during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            getObject().setSignature(new byte[0], true);
        }
    }

    private void setSessionId() {
        Optional<byte[]> exchangeHash = chooser.getContext().getExchangeHash();
        if (exchangeHash.isPresent()) {
            if (chooser.getContext().getSessionID().isEmpty()) {
                chooser.getContext().setSessionID(exchangeHash.get());
            }
        } else {
            LOGGER.warn("Exchange hash in context is empty, unable to set session id in context");
        }
    }
}
