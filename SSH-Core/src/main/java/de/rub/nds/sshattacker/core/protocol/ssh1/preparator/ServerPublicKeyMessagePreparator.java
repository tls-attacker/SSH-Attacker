/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.preparator;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.HybridKeyExchangeCombiner;
import de.rub.nds.sshattacker.core.constants.MessageIdConstantSSH1;
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat;
import de.rub.nds.sshattacker.core.crypto.hash.ExchangeHashInputHolder;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.kex.KeyAgreement;
import de.rub.nds.sshattacker.core.crypto.kex.KeyEncapsulation;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.exceptions.CryptoException;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.message.ServerPublicKeyMessage;
import de.rub.nds.sshattacker.core.protocol.util.KeyExchangeUtil;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ServerPublicKeyMessagePreparator extends SshMessagePreparator<ServerPublicKeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();
    private HybridKeyExchangeCombiner combiner;

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;

    public ServerPublicKeyMessagePreparator(
            Chooser chooser, ServerPublicKeyMessage message, HybridKeyExchangeCombiner combiner) {
        super(chooser, message, MessageIdConstantSSH1.SSH_SMSG_PUBLIC_KEY);
        this.combiner = combiner;
    }

    public void generateServerKey() throws CryptoException {
        int transientKeyLength = 786; // Bit, default Value referring to RFC
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(transientKeyLength);
            KeyPair key = keyGen.generateKeyPair();
            CustomRsaPublicKey publicKey = new CustomRsaPublicKey((RSAPublicKey) key.getPublic());
            CustomRsaPrivateKey privateKey =
                    new CustomRsaPrivateKey((RSAPrivateKey) key.getPrivate());
            this.serverKey = new SshPublicKey<>(PublicKeyFormat.SSH_RSA, publicKey, privateKey);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(
                    "Unable to generate RSA transient key - RSA key pair generator is not available");
        }
    }

    @Override
    public void prepareMessageSpecificContents() {
        LOGGER.debug("Preparring now...");
        int hostKeylenght;
        int serverKeyLenght;

        // *SSHV1*//

        // ServerKey
        SshPublicKey<?, ?> hostkey;
        try {
            generateServerKey();
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
        chooser.getContext().getSshContext().setServerKey(serverKey);
        getObject().setServerKey(serverKey);
        serverKeyLenght = serverKey.getPublicKey().getPublicExponent().bitLength();
        serverKeyLenght = serverKeyLenght + serverKey.getPublicKey().getModulus().bitLength();
        getObject().setServerKeyByteLenght(serverKeyLenght / 8);

        getObject().setServerPublicModulus(serverKey.getPublicKey().getModulus().toByteArray());
        getObject()
                .setServerPublicExponent(
                        serverKey.getPublicKey().getPublicExponent().toByteArray());

        byte[] concatenated;

        concatenated =
                KeyExchangeUtil.concatenateHybridKeys(
                        serverKey.getPublicKey().getModulus().toByteArray(),
                        serverKey.getPublicKey().getPublicExponent().toByteArray());

        getObject().setServerKeyBytes(concatenated);
        LOGGER.debug(
                "[bro] concatenated server key lenght: {} vs calculated: {}",
                concatenated.length,
                serverKeyLenght / 8);

        getObject().setServerKeyByteLenght(concatenated.length);

        LOGGER.debug(
                "[bro] ServerKey Exponent: {}",
                ArrayConverter.bytesToHexString(
                        serverKey.getPublicKey().getPublicExponent().toByteArray()));
        LOGGER.debug(
                "[bro] ServerKey Modulus: {}",
                ArrayConverter.bytesToHexString(
                        serverKey.getPublicKey().getModulus().toByteArray()));

        SshPublicKey<?, ?> hostKey = chooser.getConfig().getHostKeys().get(0);

        // Hostkey
        // Optional<SshPublicKey<?, ?>> hostKey = chooser.getContext().getSshContext().getHostKey();
        /*        if (hostKey.isPresent()) {
            CustomRsaPublicKey publicKey = (CustomRsaPublicKey) hostKey.get().getPublicKey();
            hostKeylenght = publicKey.getPublicExponent().bitLength();
            hostKeylenght = hostKeylenght + publicKey.getModulus().bitLength();
            getObject().setHostPublicModulus(publicKey.getModulus().toByteArray());
            getObject().setHostPublicExponent(publicKey.getPublicExponent().toByteArray());
            getObject().setHostKeyBits(hostKeylenght);

            LOGGER.debug(
                    "[bro] Hostkey Exponent: {}",
                    ArrayConverter.bytesToHexString(publicKey.getPublicExponent().toByteArray()));
            LOGGER.debug(
                    "[bro] Hostkey Modulus: {}",
                    ArrayConverter.bytesToHexString(publicKey.getModulus().toByteArray()));
        } else {
            LOGGER.error("Got no Hostkey!");
            throw new RuntimeException("error");
        }*/

        CustomRsaPublicKey publicKey = (CustomRsaPublicKey) hostKey.getPublicKey();
        hostKeylenght = publicKey.getPublicExponent().bitLength();
        hostKeylenght = hostKeylenght + publicKey.getModulus().bitLength();
        getObject().setHostPublicModulus(publicKey.getModulus().toByteArray());
        getObject().setHostPublicExponent(publicKey.getPublicExponent().toByteArray());
        getObject().setHostKeyByteLenght(hostKeylenght / 8);

        concatenated =
                KeyExchangeUtil.concatenateHybridKeys(
                        publicKey.getModulus().toByteArray(),
                        publicKey.getPublicExponent().toByteArray());

        getObject().setHostKeyBytes(concatenated);

        getObject().setHostKeyByteLenght(concatenated.length);

        LOGGER.debug(
                "[bro] concatenated host key lenght: {} vs calculated: {}",
                concatenated.length,
                hostKeylenght / 8);

        LOGGER.debug(
                "[bro] Hostkey Exponent: {}",
                ArrayConverter.bytesToHexString(publicKey.getPublicExponent().toByteArray()));
        LOGGER.debug(
                "[bro] Hostkey Modulus: {}",
                ArrayConverter.bytesToHexString(publicKey.getModulus().toByteArray()));

        // AntiSpoofingCookie
        getObject().setAntiSpoofingCookie(chooser.getConfig().getAntiSpoofingCookie());

        // *SSHV1*//
        /*
        KeyExchangeUtil.prepareHostKeyMessage(chooser.getContext().getSshContext(), getObject());
        prepareHybridKey();
        chooser.getHybridKeyExchange().combineSharedSecrets();
        chooser.getContext()
                .getSshContext()
                .setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        chooser.getContext()
                .getSshContext()
                .getExchangeHashInputHolder()
                .setSharedSecret(chooser.getHybridKeyExchange().getSharedSecret());
        KeyExchangeUtil.computeExchangeHash(chooser.getContext().getSshContext());
        KeyExchangeUtil.prepareExchangeHashSignatureMessage(
                chooser.getContext().getSshContext(), getObject());
        KeyExchangeUtil.setSessionId(chooser.getContext().getSshContext());
        KeyExchangeUtil.generateKeySet(chooser.getContext().getSshContext());*/
    }

    private void prepareHybridKey() {
        HybridKeyExchange keyExchange = chooser.getHybridKeyExchange();
        KeyAgreement agreement = keyExchange.getKeyAgreement();
        KeyEncapsulation encapsulation = keyExchange.getKeyEncapsulation();
        agreement.generateLocalKeyPair();
        encapsulation.encryptSharedSecret();

        ExchangeHashInputHolder inputHolder =
                chooser.getContext().getSshContext().getExchangeHashInputHolder();
        byte[] agreementBytes = agreement.getLocalKeyPair().getPublic().getEncoded();
        byte[] encapsulationBytes = encapsulation.getEncryptedSharedSecret();
        getObject().setPublicKey(agreementBytes, true);
        getObject().setCiphertext(encapsulationBytes, true);
        byte[] concatenated;
        switch (combiner) {
            case CLASSICAL_CONCATENATE_POSTQUANTUM:
                concatenated =
                        KeyExchangeUtil.concatenateHybridKeys(agreementBytes, encapsulationBytes);
                inputHolder.setHybridServerPublicKey(concatenated);
                break;
            case POSTQUANTUM_CONCATENATE_CLASSICAL:
                concatenated =
                        KeyExchangeUtil.concatenateHybridKeys(encapsulationBytes, agreementBytes);
                inputHolder.setHybridServerPublicKey(concatenated);
                break;
            default:
                LOGGER.warn("combiner is not supported. Can not set Hybrid Key.");
                break;
        }
    }
}
