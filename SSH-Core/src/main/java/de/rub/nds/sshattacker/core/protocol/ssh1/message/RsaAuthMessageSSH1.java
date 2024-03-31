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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.RsaAuthMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.RsaAuthMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.RsaAuthMessageSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.RsaAuthMessageSSHV1Serializier;
import java.io.InputStream;

public class RsaAuthMessageSSH1 extends Ssh1Message<RsaAuthMessageSSH1> {

    private ModifiableByteArray identityPublicModulus;
    private ModifiableInteger identityPublicModulusBitLenght;

    public ModifiableInteger getIdentityPublicModulusBitLenght() {
        return identityPublicModulusBitLenght;
    }

    public void setIdentityPublicModulusBitLenght(
            ModifiableInteger identityPublicModulusBitLenght) {
        this.identityPublicModulusBitLenght = identityPublicModulusBitLenght;
    }

    public void setIdentityPublicModulusBitLenght(int identityPublicModulusBitLenght) {
        this.identityPublicModulusBitLenght =
                ModifiableVariableFactory.safelySetValue(
                        this.identityPublicModulusBitLenght, identityPublicModulusBitLenght);
    }

    public ModifiableByteArray getIdentityPublicModulus() {
        return identityPublicModulus;
    }

    public void setIdentityPublicModulus(ModifiableByteArray identityPublicModulus) {
        this.identityPublicModulus = identityPublicModulus;
    }

    public void setIdentityPublicModulus(byte[] identityPublicModulus) {
        this.identityPublicModulus =
                ModifiableVariableFactory.safelySetValue(
                        this.identityPublicModulus, identityPublicModulus);
    }

    @Override
    public RsaAuthMessageSSHV1Handler getHandler(SshContext context) {
        return new RsaAuthMessageSSHV1Handler(context);
    }

    @Override
    public Ssh1MessageParser<RsaAuthMessageSSH1> getParser(SshContext context, InputStream stream) {
        return new RsaAuthMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<RsaAuthMessageSSH1> getPreparator(SshContext context) {
        return new RsaAuthMessageSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<RsaAuthMessageSSH1> getSerializer(SshContext context) {
        return new RsaAuthMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_AUTH_RSA";
    }
}
