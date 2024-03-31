/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.server.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1Message;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.handler.RsaAuthChallengeMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.parser.RsaAuthChallengeMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.preparator.RsaAuthMessageChallengeSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.server.serializer.RsaAuthChallengeMessageSSHV1Serializier;
import java.io.InputStream;

public class RsaAuthChallengeMessageSSH1 extends Ssh1Message<RsaAuthChallengeMessageSSH1> {

    private ModifiableByteArray encryptedChallenge;
    private ModifiableInteger encryptedChallengeBitLenght;

    public ModifiableInteger getEncryptedChallengeBitLenght() {
        return encryptedChallengeBitLenght;
    }

    public void setEncryptedChallengeBitLenght(ModifiableInteger encryptedChallengeBitLenght) {
        this.encryptedChallengeBitLenght = encryptedChallengeBitLenght;
    }

    public void setEncryptedChallengeBitLenght(int identityPublicModulusBitLenght) {
        encryptedChallengeBitLenght =
                ModifiableVariableFactory.safelySetValue(
                        encryptedChallengeBitLenght, identityPublicModulusBitLenght);
    }

    public ModifiableByteArray getEncryptedChallenge() {
        return encryptedChallenge;
    }

    public void setEncryptedChallenge(ModifiableByteArray encryptedChallenge) {
        this.encryptedChallenge = encryptedChallenge;
    }

    public void setIdentityPublicModulus(byte[] identityPublicModulus) {
        encryptedChallenge =
                ModifiableVariableFactory.safelySetValue(encryptedChallenge, identityPublicModulus);
    }

    @Override
    public RsaAuthChallengeMessageSSHV1Handler getHandler(SshContext sshContext) {
        return new RsaAuthChallengeMessageSSHV1Handler(sshContext);
    }

    @Override
    public Ssh1MessageParser<RsaAuthChallengeMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new RsaAuthChallengeMessageSSHV1Parser(context, stream);
    }

    @Override
    public Ssh1MessagePreparator<RsaAuthChallengeMessageSSH1> getPreparator(SshContext sshContext) {
        return new RsaAuthMessageChallengeSSHV1Preparator(sshContext.getChooser(), this);
    }

    @Override
    public Ssh1MessageSerializer<RsaAuthChallengeMessageSSH1> getSerializer(SshContext sshContext) {
        return new RsaAuthChallengeMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_AUTH_RSA_CHALLENGE";
    }
}
