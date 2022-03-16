/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.crypto.hash.EcdhExchangeHash;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHash;
import de.rub.nds.sshattacker.core.crypto.kex.EcdhKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.HostKey;
import de.rub.nds.sshattacker.core.crypto.signature.SignatureFactory;
import de.rub.nds.sshattacker.core.crypto.signature.SigningSignature;
import de.rub.nds.sshattacker.core.crypto.util.PublicKeyHelper;
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.message.EcdhKeyExchangeReplyMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;

public class EcdhKeyExchangeReplyMessagePreparator
        extends SshMessagePreparator<EcdhKeyExchangeReplyMessage> {

    public EcdhKeyExchangeReplyMessagePreparator(
            Chooser chooser, EcdhKeyExchangeReplyMessage message) {
        super(chooser, message);
    }

    @Override
    public void prepareMessageSpecificContents() {
        getObject().setMessageID(MessageIDConstant.SSH_MSG_KEX_ECDH_REPLY);
        prepareHostKey();
        prepareEphemeralPublicKey();
        updateExchangeHashWithSharedSecret();
        prepareSignature();
        setSessionId();
    }

    private void prepareHostKey() {
        HostKey serverHostKey = chooser.getNegotiatedServerHostKey();
        byte[] encodedServerHostKey = PublicKeyHelper.encode(serverHostKey);
        getObject().setHostKey(encodedServerHostKey, true);
        chooser.getContext().getExchangeHashInstance().setServerHostKey(encodedServerHostKey);
    }

    private void prepareEphemeralPublicKey() {
        if (chooser.getContext().getKeyExchangeInstance().isPresent()) {
            KeyExchange keyExchange = chooser.getContext().getKeyExchangeInstance().get();
            if (keyExchange instanceof EcdhKeyExchange) {
                EcdhKeyExchange ecdhKeyExchange = (EcdhKeyExchange) keyExchange;
                ecdhKeyExchange.generateLocalKeyPair();
                getObject()
                        .setEphemeralPublicKey(
                                ecdhKeyExchange.getLocalKeyPair().getPublic().getEncoded(), true);
                // Compute shared secret if remote public key is available
                if (ecdhKeyExchange.getRemotePublicKey() != null) {
                    ecdhKeyExchange.computeSharedSecret();
                } else {
                    raisePreparationException(
                            "No remote public key is present, unable to compute shared secret");
                }
                // Update exchange hash with local public key
                ExchangeHash exchangeHash = chooser.getContext().getExchangeHashInstance();
                if (exchangeHash instanceof EcdhExchangeHash) {
                    ((EcdhExchangeHash) exchangeHash)
                            .setServerECDHPublicKey(ecdhKeyExchange.getLocalKeyPair().getPublic());
                } else {
                    raisePreparationException(
                            "Exchange hash instance is not an instance of EcdhExchangeHash, unable to update exchange hash");
                }
            } else {
                raisePreparationException(
                        "Key exchange is not an instance of EcdhKeyExchange, unable to generate local keypair and compute shared secret");
            }
        } else {
            raisePreparationException(
                    "Key exchange instance is not present, unable to generate local keypair and compute shared secret");
        }
    }

    private void updateExchangeHashWithSharedSecret() {
        Optional<KeyExchange> keyExchange = chooser.getContext().getKeyExchangeInstance();
        if (keyExchange.isPresent() && keyExchange.get().isComplete()) {
            chooser.getContext()
                    .getExchangeHashInstance()
                    .setSharedSecret(keyExchange.get().getSharedSecret());
        } else {
            raisePreparationException(
                    "Key exchange instance is either not present or not ready yet, unable to update exchange hash with shared secret");
        }
    }

    private void prepareSignature() {
        HostKey serverHostKey = chooser.getNegotiatedServerHostKey();
        ExchangeHash exchangeHash = chooser.getContext().getExchangeHashInstance();
        SigningSignature signingSignature;
        try {
            signingSignature = SignatureFactory.getSigningSignature(serverHostKey);
            SignatureEncoding signatureEncoding =
                    serverHostKey.getPublicKeyAlgorithm().getSignatureEncoding();
            byte[] encodedSignature =
                    ArrayConverter.intToBytes(
                            signatureEncoding.getName().length(),
                            DataFormatConstants.STRING_SIZE_LENGTH);
            encodedSignature =
                    ArrayConverter.concatenate(
                            encodedSignature,
                            signatureEncoding.getName().getBytes(StandardCharsets.US_ASCII));
            byte[] rawSignature = signingSignature.sign(exchangeHash.get());
            encodedSignature =
                    ArrayConverter.concatenate(
                            encodedSignature,
                            ArrayConverter.intToBytes(
                                    rawSignature.length, DataFormatConstants.STRING_SIZE_LENGTH));
            encodedSignature = ArrayConverter.concatenate(encodedSignature, rawSignature);
            getObject().setSignature(encodedSignature, true);
        } catch (NoSuchAlgorithmException e) {
            raisePreparationException(
                    "Unsupported host key algorithm used during signature generation");
        } catch (CryptoException e) {
            raisePreparationException(
                    "Unexpected CryptoException caught during signature generation");
        }
    }

    private void setSessionId() {
        ExchangeHash exchangeHash = chooser.getContext().getExchangeHashInstance();
        if (chooser.getContext().getSessionID().isEmpty()) {
            try {
                chooser.getContext().setSessionID(exchangeHash.get());
            } catch (AdjustmentException e) {
                raisePreparationException(e.getMessage());
            }
        }
    }
}
