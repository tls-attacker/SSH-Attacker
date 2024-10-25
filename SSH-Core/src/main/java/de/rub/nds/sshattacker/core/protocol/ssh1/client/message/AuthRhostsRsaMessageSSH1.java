/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.handler.AuthRhostsRsaMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.parser.AuthRhostsRsaMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.preparator.AuthRhostsRsaMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.serializer.AuthRhostsRsaMessageSSHV1Serializier;
import java.io.InputStream;

public class AuthRhostsRsaMessageSSH1 extends Ssh1Message<AuthRhostsRsaMessageSSH1> {

    private ModifiableInteger clientHostKeyBits;
    private ModifiableString username;
    private ModifiableByteArray hostPublicExponent;
    private ModifiableByteArray hostPublicModulus;

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
        hostPublicModulus =
                ModifiableVariableFactory.safelySetValue(hostPublicModulus, publicModulus);
    }

    public ModifiableString getUsername() {
        return username;
    }

    public void setUsername(ModifiableString username) {
        this.username = username;
    }

    public void setUsername(String username) {
        this.username = ModifiableVariableFactory.safelySetValue(this.username, username);
    }

    public ModifiableInteger getClientHostKeyBits() {
        return clientHostKeyBits;
    }

    public void setClientHostKeyBits(ModifiableInteger clientHostKeyBits) {
        this.clientHostKeyBits = clientHostKeyBits;
    }

    public void setClientHostKeyBits(int clientHostKeyBits) {
        this.clientHostKeyBits =
                ModifiableVariableFactory.safelySetValue(this.clientHostKeyBits, clientHostKeyBits);
    }

    @Override
    public AuthRhostsRsaMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new AuthRhostsRsaMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<AuthRhostsRsaMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new AuthRhostsRsaMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<AuthRhostsRsaMessageSSH1> getPreparator(SshContext sshContext) {
        return new AuthRhostsRsaMessageSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<AuthRhostsRsaMessageSSH1> getSerializer(SshContext sshContext) {
        return new AuthRhostsRsaMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_AUTH_RHOSTS_RSA";
    }
}
