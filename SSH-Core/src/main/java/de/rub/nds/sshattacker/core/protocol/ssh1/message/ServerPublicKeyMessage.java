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
import de.rub.nds.sshattacker.core.constants.AuthenticationMethodSSHv1;
import de.rub.nds.sshattacker.core.constants.CipherMethod;
import de.rub.nds.sshattacker.core.constants.ProtocolFlag;
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
import java.util.List;

public class ServerPublicKeyMessage extends SshMessage<ServerPublicKeyMessage> {

    // ServerKey
    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey;
    private ModifiableInteger serverKeyByteLength;
    private ModifiableByteArray serverPublicExponent;
    private ModifiableByteArray serverPublicModulus;

    private ModifiableInteger serverKeyBitLenght;
    private ModifiableByteArray serverKeyBytes;

    // Host Key
    private SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> hostKey;
    private ModifiableInteger hostKeyByteLenght;
    private ModifiableByteArray hostPublicExponent;
    private ModifiableByteArray hostPublicModulus;
    private ModifiableByteArray hostKeyBytes;

    private ModifiableInteger hostKeyBitLenght;

    // Other Values
    private ModifiableByteArray antiSpoofingCookie;

    private ModifiableInteger protocolFlagMask;

    private ModifiableInteger cipherMask;
    private ModifiableInteger authMask;

    private List<CipherMethod> supportedCipherMethods;
    private List<ProtocolFlag> chosenProtocolFlags;

    private List<AuthenticationMethodSSHv1> supportedAuthenticationMethods;

    public ModifiableByteArray getServerKeyBytes() {
        return serverKeyBytes;
    }

    public void setAntiSpoofingCookie(ModifiableByteArray antiSpoofingCookie) {
        this.antiSpoofingCookie = antiSpoofingCookie;
    }

    public void setAntiSpoofingCookie(byte[] antiSpoofingCookie) {
        this.antiSpoofingCookie =
                ModifiableVariableFactory.safelySetValue(
                        this.antiSpoofingCookie, antiSpoofingCookie);
    }

    public SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> getHostKey() {
        return hostKey;
    }

    public void setHostKey(SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> hostKey) {
        this.hostKey = hostKey;
        setHostPublicModulus(this.hostKey.getPublicKey().getModulus().toByteArray());
        setHostPublicExponent(this.hostKey.getPublicKey().getPublicExponent().toByteArray());
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

    public SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> getServerKey() {
        return serverKey;
    }

    public void setServerKey(SshPublicKey<CustomRsaPublicKey, CustomRsaPrivateKey> serverKey) {
        this.serverKey = serverKey;
        setServerPublicModulus(this.serverKey.getPublicKey().getModulus().toByteArray());
        setServerPublicExponent(this.serverKey.getPublicKey().getPublicExponent().toByteArray());

        // this.serverPublicExponent = serverKey.getPublicKey().getPublicExponent().byteValue();
        // //toModifiableByteArry....
        // this.serverPublicModulus = serverKey.getPublicKey().getModulus().byteValue();
        // //toModifiableByteArry...
    }

    public void setServerKeyBytes(byte[] serverKeyBytes) {
        this.serverKeyBytes =
                ModifiableVariableFactory.safelySetValue(this.serverKeyBytes, serverKeyBytes);
        ;
    }

    public ModifiableByteArray getAntiSpoofingCookie() {
        return antiSpoofingCookie;
    }

    // *SSHV1*//

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

    public ModifiableInteger getProtocolFlagMask() {
        return protocolFlagMask;
    }

    public void setProtocolFlagMask(ModifiableInteger protocolFlagMask) {
        this.protocolFlagMask = protocolFlagMask;
    }

    public void setProtocolFlagMask(int protocolFlags) {
        this.protocolFlagMask =
                ModifiableVariableFactory.safelySetValue(this.protocolFlagMask, protocolFlags);
    }

    public ModifiableInteger getCipherMask() {
        return cipherMask;
    }

    public void setCipherMask(ModifiableInteger cipherMask) {
        this.cipherMask = cipherMask;
    }

    public void setCipherMask(int cipherMask) {
        this.cipherMask = ModifiableVariableFactory.safelySetValue(this.cipherMask, cipherMask);
    }

    public ModifiableInteger getAuthMask() {
        return authMask;
    }

    public void setAuthMask(ModifiableInteger authMask) {
        this.authMask = authMask;
    }

    public void setAuthMask(int authMask) {
        this.authMask = ModifiableVariableFactory.safelySetValue(this.authMask, authMask);
    }

    public List<CipherMethod> getSupportedCipherMethods() {
        return supportedCipherMethods;
    }

    public void setSupportedCipherMethods(List<CipherMethod> supportedCipherMethods) {
        this.supportedCipherMethods = supportedCipherMethods;
    }

    public List<AuthenticationMethodSSHv1> getSupportedAuthenticationMethods() {
        return supportedAuthenticationMethods;
    }

    public void setSupportedAuthenticationMethods(
            List<AuthenticationMethodSSHv1> supportedAuthenticationMethods) {
        this.supportedAuthenticationMethods = supportedAuthenticationMethods;
    }

    public ModifiableInteger getServerKeyBitLenght() {
        return serverKeyBitLenght;
    }

    public void setServerKeyBitLenght(ModifiableInteger serverKeyBitLenght) {
        this.serverKeyBitLenght = serverKeyBitLenght;
    }

    public void setServerKeyBitLenght(int serverKeyBitLenght) {
        this.serverKeyBitLenght =
                ModifiableVariableFactory.safelySetValue(
                        this.serverKeyBitLenght, serverKeyBitLenght);
    }

    public ModifiableInteger getHostKeyBitLenght() {
        return hostKeyBitLenght;
    }

    public void setHostKeyBitLenght(ModifiableInteger hostKeyBitLenght) {
        this.hostKeyBitLenght = hostKeyBitLenght;
    }

    public void setHostKeyBitLenght(int hostKeyBitLenght) {
        this.hostKeyBitLenght =
                ModifiableVariableFactory.safelySetValue(this.hostKeyBitLenght, hostKeyBitLenght);
    }

    public List<ProtocolFlag> getChosenProtocolFlags() {
        return chosenProtocolFlags;
    }

    public void setChosenProtocolFlags(List<ProtocolFlag> chosenProtocolFlags) {
        this.chosenProtocolFlags = chosenProtocolFlags;
    }

    private ModifiableInteger publicKeyLength;

    @Override
    public ServerPublicKeyMessageHandler getHandler(SshContext context) {
        return new ServerPublicKeyMessageHandler(context);
    }

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
        return new ServerPublicKeyMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "SMGS_PUBLIC_KEY";
    }
}
