/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPrivateKey;
import de.rub.nds.sshattacker.core.crypto.keys.CustomRsaPublicKey;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ServerPublicKeyMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ServerPublicKeyMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ServerPublicKeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ServerPublicKeyMessageSerializer;
import java.io.InputStream;

public class ServerPublicKeyMessage extends SshMessage<ServerPublicKeyMessage> {

    public ModifiableByteArray getAntiSpoofingCookie() {
        return antiSpoofingCookie;
    }

    public void setAntiSpoofingCookie(ModifiableByteArray antiSpoofingCookie) {
        this.antiSpoofingCookie = antiSpoofingCookie;
    }

    public void setAntiSpoofingCookie(byte[] antiSpoofingCookie) {
        this.antiSpoofingCookie =
                ModifiableVariableFactory.safelySetValue(
                        this.antiSpoofingCookie, antiSpoofingCookie);
    }

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> hostKey;

    public void setHostKey(SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> hostKey) {
        this.hostKey = hostKey;
    }

    public SshPublicKey<?, ?> getServerKey() {
        return serverKey;
    }

    public void setServerKey(SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey) {
        this.serverKey = serverKey;
        // this.serverPublicExponent = serverKey.getPublicKey().getPublicExponent().byteValue();
        // //toModifiableByteArry....
        // this.serverPublicModulus = serverKey.getPublicKey().getModulus().byteValue();
        // //toModifiableByteArry...
    }

    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;

    // *SSHV1*//
    private ModifiableByteArray antiSpoofingCookie;
    private ModifiableInteger serverKeyByteLength;

    public ModifiableByteArray getServerPublicExponent() {
        return serverPublicExponent;
    }

    public void setServerPublicExponent(ModifiableByteArray serverPublicExponent) {
        this.serverPublicExponent = serverPublicExponent;
    }

    public void setServerPublicExponent(byte[] serverPublicExponent) {
        this.serverPublicExponent =
                ModifiableVariableFactory.safelySetValue(
                        this.serverPublicExponent, serverPublicExponent);
    }

    public ModifiableByteArray getServerPublicModulus() {
        return serverPublicModulus;
    }

    public void setServerPublicModulus(ModifiableByteArray serverPublicModulus) {
        this.serverPublicModulus = serverPublicModulus;
    }

    public void setServerPublicModulus(byte[] serverPublicModulus) {
        this.serverPublicModulus =
                ModifiableVariableFactory.safelySetValue(
                        this.serverPublicModulus, serverPublicModulus);
    }

    private ModifiableByteArray serverPublicExponent;
    private ModifiableByteArray serverPublicModulus;

    public ModifiableInteger getServerKeyByteLength() {
        return serverKeyByteLength;
    }

    public void setServerKeyByteLength(ModifiableInteger serverKeyByteLength) {
        this.serverKeyByteLength = serverKeyByteLength;
    }

    public void setServerKeyByteLenght(int serverKeyBits) {
        this.serverKeyByteLength =
                ModifiableVariableFactory.safelySetValue(this.serverKeyByteLength, serverKeyBits);
    }

    public ModifiableInteger getHostKeyByteLenght() {
        return hostKeyByteLenght;
    }

    public void setHostKeyByteLenght(ModifiableInteger hostKeyByteLenght) {
        this.hostKeyByteLenght = hostKeyByteLenght;
    }

    public void setHostKeyByteLenght(int hostKeyBits) {
        this.hostKeyByteLenght =
                ModifiableVariableFactory.safelySetValue(this.hostKeyByteLenght, hostKeyBits);
    }

    private ModifiableInteger hostKeyByteLenght;

    public ModifiableByteArray getHostPublicExponent() {
        return hostPublicExponent;
    }

    public void setHostPublicExponent(ModifiableByteArray hostPublicExponent) {
        this.hostPublicExponent = hostPublicExponent;
    }

    public void setHostPublicExponent(byte[] hostPublicExponent) {
        this.hostPublicExponent =
                ModifiableVariableFactory.safelySetValue(
                        this.hostPublicExponent, hostPublicExponent);
    }

    public ModifiableByteArray getHostPublicModulus() {
        return hostPublicModulus;
    }

    public void setHostPublicModulus(ModifiableByteArray hostPublicModulus) {
        this.hostPublicModulus = hostPublicModulus;
    }

    public void setHostPublicModulus(byte[] publicModulus) {
        this.hostPublicModulus =
                ModifiableVariableFactory.safelySetValue(this.hostPublicModulus, publicModulus);
    }

    private ModifiableByteArray hostPublicExponent;
    private ModifiableByteArray hostPublicModulus;
    private ModifiableInteger protocolFlags;
    private ModifiableInteger cipherMask;
    private ModifiableInteger authMask;
    // *SSHV1*//

    public ModifiableByteArray getHostKeyBytes() {
        return hostKeyBytes;
    }

    public void setHostKeyBytes(ModifiableByteArray hostKeyBytes) {
        this.hostKeyBytes = hostKeyBytes;
    }

    public void setHostKeyBytes(byte[] hostKeyBytes) {
        this.hostKeyBytes =
                ModifiableVariableFactory.safelySetValue(this.hostKeyBytes, hostKeyBytes);
    }

    private ModifiableByteArray hostKeyBytes;

    public ModifiableByteArray getServerKeyBytes() {
        return serverKeyBytes;
    }

    public void setServerKeyBytes(ModifiableByteArray serverKeyBytes) {
        this.serverKeyBytes = serverKeyBytes;
    }

    public void setServerKeyBytes(byte[] serverKeyBytes) {
        this.serverKeyBytes =
                ModifiableVariableFactory.safelySetValue(this.serverKeyBytes, serverKeyBytes);
        ;
    }

    private ModifiableByteArray serverKeyBytes;

    private ModifiableInteger publicKeyLength;
    private ModifiableByteArray publicKey;

    private ModifiableInteger combinedKeyShareLength;
    private ModifiableByteArray combinedKeyShare;

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public ModifiableInteger getPublicKeyLength() {
        return publicKeyLength;
    }

    public void setPublicKeyLength(ModifiableInteger publicKeyLength) {
        this.publicKeyLength = publicKeyLength;
    }

    public void setPublicKeyLength(int publicKeyLength) {
        this.publicKeyLength =
                ModifiableVariableFactory.safelySetValue(this.publicKeyLength, publicKeyLength);
    }

    public ModifiableByteArray getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        setPublicKey(publicKey, false);
    }

    public void setPublicKey(ModifiableByteArray publicKey, boolean adjustLengthField) {
        this.publicKey = publicKey;
        if (adjustLengthField) {
            setPublicKeyLength(this.publicKey.getValue().length);
        }
    }

    public void setPublicKey(byte[] publicKey, boolean adjustLengthField) {
        this.publicKey = ModifiableVariableFactory.safelySetValue(this.publicKey, publicKey);
        if (adjustLengthField) {
            setPublicKeyLength(this.publicKey.getValue().length);
        }
    }

    public ModifiableInteger getCombinedKeyShareLength() {
        return combinedKeyShareLength;
    }

    public void setCombinedKeyShareLength(ModifiableInteger combinedKeyShareLength) {
        this.combinedKeyShareLength = combinedKeyShareLength;
    }

    public void setCiphertextLength(int ciphertextLength) {
        this.combinedKeyShareLength =
                ModifiableVariableFactory.safelySetValue(
                        this.combinedKeyShareLength, ciphertextLength);
    }

    public ModifiableByteArray getCombinedKeyShare() {
        return combinedKeyShare;
    }

    public void setCombinedKeyShare(byte[] combinedKeyShare) {
        setCiphertext(combinedKeyShare, false);
    }

    public void setCiphertext(ModifiableByteArray ciphertext, boolean adjustLengthField) {
        this.combinedKeyShare = ciphertext;
        if (adjustLengthField) {
            setCiphertextLength(this.combinedKeyShare.getValue().length);
        }
    }

    public void setCiphertext(byte[] ciphertext, boolean adjustLengthField) {
        this.combinedKeyShare =
                ModifiableVariableFactory.safelySetValue(this.combinedKeyShare, ciphertext);
        if (adjustLengthField) {
            setCiphertextLength(this.combinedKeyShare.getValue().length);
        }
    }

    @Override
    public ServerPublicKeyMessageHandler getHandler(SshContext context) {
        return new ServerPublicKeyMessageHandler(context);
    }

    /*@Override
    public SshMessageParser<HybridKeyExchangeReplyMessage> getParser(SshContext context, InputStream stream) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeReplyMessageParser(
                array, kex.getCombiner(), kex.getPkAgreementLength(), kex.getCiphertextLength());
    }*/

    @Override
    public SshMessageParser<ServerPublicKeyMessage> getParser(
            SshContext context, InputStream stream) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new ServerPublicKeyMessageParser(context, stream);
    }

    @Override
    public SshMessagePreparator<ServerPublicKeyMessage> getPreparator(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new ServerPublicKeyMessagePreparator(context.getChooser(), this, kex.getCombiner());
    }

    @Override
    public SshMessageSerializer<ServerPublicKeyMessage> getSerializer(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new ServerPublicKeyMessageSerializer(this, kex.getCombiner());
    }

    @Override
    public String toShortString() {
        return "HYB_KEX_REPL";
    }
}
