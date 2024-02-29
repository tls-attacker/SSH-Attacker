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
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.AuthRhostsRsaMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.AuthRhostsRsaMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.AuthRhostsRsaMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.AuthRhostsRsaMessageSSHV1Serializier;
import java.io.InputStream;

public class AuthRhostsRsaMessageSSH1 extends SshMessage<AuthRhostsRsaMessageSSH1> {

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
        this.hostPublicModulus =
                ModifiableVariableFactory.safelySetValue(this.hostPublicModulus, publicModulus);
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
    public AuthRhostsRsaMessageSSHV1Handler getHandler(SshContext context) {
        return new AuthRhostsRsaMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<AuthRhostsRsaMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new AuthRhostsRsaMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<AuthRhostsRsaMessageSSH1> getPreparator(SshContext context) {
        return new AuthRhostsRsaMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<AuthRhostsRsaMessageSSH1> getSerializer(SshContext context) {
        return new AuthRhostsRsaMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_MSG_CHANNEL_OPEN_FAILURE";
    }
}
