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
import de.rub.nds.sshattacker.core.constants.CipherMethod;
import de.rub.nds.sshattacker.core.constants.ProtocolFlag;
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.ClientSessionKeyMessageHandler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.ClientSessionKeyMessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.ClientSessionKeyMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.ClientSessionKeyMessageSerializer;
import java.io.InputStream;
import java.util.List;

public class ClientSessionKeyMessage extends SshMessage<ClientSessionKeyMessage> {

    private CipherMethod chosenCipherMethod;
    private ModifiableByteArray antiSpoofingCookie;
    private ModifiableByteArray sshv1SessionID;
    private ModifiableByteArray encryptedSessioKey;
    private ModifiableByteArray plaintextSessioKey;
    private List<ProtocolFlag> chosenProtocolFlags;
    private ModifiableInteger protocolFlagMask;

    public CipherMethod getChosenCipherMethod() {
        return chosenCipherMethod;
    }

    public void setChosenCipherMethod(CipherMethod chosenCipherMethod) {
        this.chosenCipherMethod = chosenCipherMethod;
    }

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

    public ModifiableByteArray getEncryptedSessioKey() {
        return encryptedSessioKey;
    }

    public void setEncryptedSessioKey(ModifiableByteArray encryptedSessioKey) {
        this.encryptedSessioKey = encryptedSessioKey;
    }

    public void setEncryptedSessioKey(byte[] encryptedSessioKey) {
        this.encryptedSessioKey =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptedSessioKey, encryptedSessioKey);
    }

    public ModifiableByteArray getPlaintextSessioKey() {
        return plaintextSessioKey;
    }

    public void setPlaintextSessioKey(ModifiableByteArray plaintextSessioKey) {
        this.plaintextSessioKey = plaintextSessioKey;
    }

    public List<ProtocolFlag> getChosenProtocolFlags() {
        return chosenProtocolFlags;
    }

    public void setChosenProtocolFlags(List<ProtocolFlag> chosenProtocolFlags) {
        this.chosenProtocolFlags = chosenProtocolFlags;
    }

    public ModifiableInteger getProtocolFlagMask() {
        return protocolFlagMask;
    }

    public void setProtocolFlagMask(ModifiableInteger protocolFlagMask) {
        this.protocolFlagMask = protocolFlagMask;
    }

    public void setProtocolFlagMask(int protocolFlagMask) {
        this.protocolFlagMask =
                ModifiableVariableFactory.safelySetValue(this.protocolFlagMask, protocolFlagMask);
    }

    public ModifiableByteArray getSshv1SessionID() {
        return sshv1SessionID;
    }

    public void setSshv1SessionID(ModifiableByteArray sshv1SessionID) {
        this.sshv1SessionID = sshv1SessionID;
    }

    public void setSshv1SessionID(byte[] sshv1SessionID) {
        this.sshv1SessionID =
                ModifiableVariableFactory.safelySetValue(this.sshv1SessionID, sshv1SessionID);
    }

    @Override
    public ClientSessionKeyMessageHandler getHandler(SshContext context) {
        return new ClientSessionKeyMessageHandler(context);
    }

    @Override
    public SshMessageParser<ClientSessionKeyMessage> getParser(
            SshContext context, InputStream stream) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new ClientSessionKeyMessageParser(context, stream);
    }

    @Override
    public SshMessagePreparator<ClientSessionKeyMessage> getPreparator(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new ClientSessionKeyMessagePreparator(context.getChooser(), this, kex.getCombiner());
    }

    @Override
    public SshMessageSerializer<ClientSessionKeyMessage> getSerializer(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new ClientSessionKeyMessageSerializer(this, kex.getCombiner());
    }

    @Override
    public String toShortString() {
        return "CMSG_SESSION_KEY";
    }
}
