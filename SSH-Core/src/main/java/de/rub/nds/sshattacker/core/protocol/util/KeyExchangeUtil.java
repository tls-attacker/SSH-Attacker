/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm;
import de.rub.nds.sshattacker.core.constants.SignatureEncoding;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.KeyAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.crypto.signature.*;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.exceptions.MissingExchangeHashInputException;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySet;
import de.rub.nds.sshattacker.core.packet.cipher.keys.KeySetGenerator;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExchangeHashSignatureMessage;
import de.rub.nds.sshattacker.core.protocol.transport.message.HostKeyMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * A utility class to reduce redundancy in handlers and preparators of key exchange messages by
 * implementing common functionality like host key signing, signature verification, shared secret
 * handling, and more. A utility class is preferred over inheritance as messages do not share a
 * common structure and the functionality is used in both, handlers and preparators requiring at
 * least two similar implementations for most methods.
 */
public final class KeyExchangeUtil {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeyExchangeUtil() {}

    /**
     * Prepares a host key message by selecting a suitable host key, updating context, and adjusting
     * the encoded host key bytes of the provided message.
     *
     * @param context SSH context
     * @param message Message to prepare
     */
    public static void prepareHostKeyMessage(SshContext context, HostKeyMessage message) {
        SshPublicKey<?, ?> serverHostKey = context.getChooser().getNegotiatedHostKey();
        context.setHostKey(serverHostKey);
        context.getExchangeHashInputHolder().setServerHostKey(serverHostKey);
        message.setHostKeyBytes(PublicKeyHelper.encode(serverHostKey), true);
    }

    /**
     * Handles a host key message by updating the context accordingly.
     *
     * @param context SSH context to update
     * @param message The message to handle
     */
    public static void handleHostKeyMessage(SshContext context, HostKeyMessage message) {
        SshPublicKey<?, ?> hostKey =
                PublicKeyHelper.parse(
                        context.getChooser().getHostKeyAlgorithm().getKeyFormat(),
                        message.getHostKeyBytes().getValue());
        context.setHostKey(hostKey);
        context.getExchangeHashInputHolder().setServerHostKey(hostKey);
    }

    /**
     * Prepares an exchange hash signature message by signing the exchange hash present in the
     * context with a suitable host key. The raw signature is formatted according to RFC 4253 prior
     * to updating the message.
     *
     * @param context SSH context
     * @param message Message to prepare
     */
    public static void prepareExchangeHashSignatureMessage(
            SshContext context, ExchangeHashSignatureMessage message) {
        SshPublicKey<?, ?> serverHostKey = context.getChooser().getNegotiatedHostKey();
        Optional<byte[]> exchangeHash = context.getExchangeHash();
        SigningSignature signingSignature;
        try {
            signingSignature =
                    SignatureFactory.getSigningSignature(
                            context.getChooser().getHostKeyAlgorithm(), serverHostKey);
            SignatureEncoding signatureEncoding =
                    context.getChooser().getHostKeyAlgorithm().getSignatureEncoding();
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
            // Adjust context with computed exchange hash signature
            context.setServerExchangeHashSignature(signatureOutput.toByteArray());
            context.setServerExchangeHashSignatureValid(true);
            message.setSignature(signatureOutput.toByteArray(), true);
        } catch (CryptoException e) {
            LOGGER.error(
                    "An unexpected cryptographic exception occurred during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            context.setServerExchangeHashSignature(null);
            context.setServerExchangeHashSignatureValid(null);
            message.setSignature(new byte[0], true);
        } catch (IOException e) {
            LOGGER.error(
                    "An unexpected IOException occured during signature generation, workflow will continue but signature is left blank");
            LOGGER.debug(e);
            context.setServerExchangeHashSignature(null);
            context.setServerExchangeHashSignatureValid(null);
            message.setSignature(new byte[0], true);
        }
    }

    /**
     * Handles an exchange hash signature message by updating the context and verifying the
     * signature.
     *
     * @param context SSH context to update
     * @param message The message to handle
     */
    public static void handleExchangeHashSignatureMessage(
            SshContext context, ExchangeHashSignatureMessage message) {
        context.setServerExchangeHashSignature(message.getSignature().getValue());
        verifySignature(context, message);
    }

    /**
     * Verifies the signature of the given message under the context instance. Called as part of the
     * public handleExchangeHashSignatureMessage() function.
     *
     * @param context SSH context
     * @param message Message object containing the signature to verify
     */
    private static void verifySignature(SshContext context, ExchangeHashSignatureMessage message) {

        Config SshConfig = context.getChooser().getConfig();

        byte[] exchangeHash = context.getExchangeHash().orElse(new byte[0]);
        PublicKeyAlgorithm hostKeyAlgorithm = context.getChooser().getHostKeyAlgorithm();
        Optional<SshPublicKey<?, ?>> hostKey = context.getHostKey();
        if (hostKey.isPresent()) {
            RawSignature signature =
                    new SignatureParser(message.getSignature().getValue(), 0).parse();
            try {
                VerifyingSignature verifyingSignature =
                        SignatureFactory.getVerifyingSignature(hostKeyAlgorithm, hostKey.get());
                LOGGER.info(hostKey.get());

                SshConfig.setExchangeHashSignatureServer(signature.getSignatureBytes());
                if (verifyingSignature.verify(exchangeHash, signature.getSignatureBytes())) {
                    LOGGER.info(
                            "Exchange hash signature verification successful: Signature is valid.");
                    context.setServerExchangeHashSignatureValid(true);
                } else {
                    LOGGER.warn(
                            "Exchange hash signature verification failed: Signature is invalid - continuing anyway.");
                    context.setServerExchangeHashSignatureValid(false);
                }
            } catch (CryptoException e) {
                LOGGER.error(
                        "Exchange hash signature verification failed: Unexpected cryptographic error - see debug for more details.");
                LOGGER.debug(e);
                // Unable to determine whether signature is valid, set to null instead
                context.setServerExchangeHashSignatureValid(null);
            }
        } else {
            LOGGER.error("Exchange hash signature verification failed: Server host key missing.");
            // Unable to determine whether signature is valid, set to null instead
            context.setServerExchangeHashSignatureValid(null);
        }
    }

    /**
     * Computes the shared secret and updates the context and exchange hash input accordingly. Used
     * for KeyAgreement Schemes.
     *
     * @param context SSH context to update
     * @param keyAgreement Key exchange instance for shared secret computation
     */
    public static void computeSharedSecret(SshContext context, KeyAgreement keyAgreement) {
        try {

            Config sshConfig = context.getChooser().getConfig();

            keyAgreement.computeSharedSecret();

            if (sshConfig.getIsInvalidCurveAttack()) {
                // Replce the sharedsecret we use for our exchange Hash if the invalid curve attack
                // is used
                context.setSharedSecret(sshConfig.getCustomSharedSecret());
                context.getExchangeHashInputHolder()
                        .setSharedSecret(sshConfig.getCustomSharedSecret());
            } else {
                context.setSharedSecret(keyAgreement.getSharedSecret());
                context.getExchangeHashInputHolder()
                        .setSharedSecret(keyAgreement.getSharedSecret());
            }

        } catch (CryptoException e) {
            LOGGER.warn("Key exchange instance is not ready yet, unable to compute shared secret");
            LOGGER.debug(e);
        }
    }

    /**
     * Generates the shared secret and updates the context and exchange hash input accordingly. Used
     * for KeyEncapsulation Schemes.
     *
     * @param context SSH context to update
     * @param keyEncapsulation Key exchange instance for shared secret generation
     */
    public static void generateSharedSecret(SshContext context, KeyEncapsulation keyEncapsulation) {
        keyEncapsulation.generateSharedSecret();
        context.setSharedSecret(keyEncapsulation.getSharedSecret());
        context.getExchangeHashInputHolder().setSharedSecret(keyEncapsulation.getSharedSecret());
    }

    /**
     * Computes the exchange hash based on an ExchangeHashInputHolder instance and the negotiated
     * key exchange algorithm.
     *
     * @param context SSH context containing the ExchangeHashInputHolder used as an input to
     *     exchange hash computation
     */
    public static void computeExchangeHash(SshContext context) {
        try {
            context.setExchangeHash(
                    ExchangeHash.computeHash(
                            context, context.getChooser().getKeyExchangeAlgorithm()));

            //Get the exchange hash input holder for the client exchange hash we will modify if we use the invalid curve attack
            if(context.getChooser().getConfig().getIsInvalidCurveAttack()){
                context.getChooser()
                        .getConfig()
                        .setExchangeHashInputHolderClient(context.getExchangeHashInputHolder());
            }

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

    /**
     * Updates the context by setting the session id if missing. This requires the exchange hash
     * field to be present.
     *
     * @param context SSH context to set the session id for
     */
    public static void setSessionId(SshContext context) {
        Optional<byte[]> exchangeHash = context.getExchangeHash();
        if (exchangeHash.isPresent()) {
            if (context.getSessionID().isEmpty()) {
                context.setSessionID(exchangeHash.get());
            }
        } else {
            LOGGER.warn("Exchange hash in context is empty, unable to set session id in context");
        }
    }

    /**
     * Generates a new key set from context and stores it in the context.
     *
     * @param context SSH context
     */
    public static void generateKeySet(SshContext context) {
        KeySet keySet = KeySetGenerator.generateKeySet(context);
        context.setKeySet(keySet);
    }

    /**
     * Concatenates two keys.
     *
     * @param first first key
     * @param second second key
     * @return first || second
     */
    public static byte[] concatenateHybridKeys(byte[] first, byte[] second) {
        return ArrayConverter.concatenate(first, second);
    }
}
