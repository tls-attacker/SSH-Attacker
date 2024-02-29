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
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.ssh1.handler.RsaAuthChallengeMessageSSHV1Handler;
import de.rub.nds.sshattacker.core.protocol.ssh1.parser.RsaAuthChallengeMessageSSHV1Parser;
import de.rub.nds.sshattacker.core.protocol.ssh1.preparator.RsaAuthMessageChallengeSSHV1Preparator;
import de.rub.nds.sshattacker.core.protocol.ssh1.serializer.RsaAuthChallengeMessageSSHV1Serializier;
import java.io.InputStream;

public class RsaAuthChallengeMessageSSH1 extends SshMessage<RsaAuthChallengeMessageSSH1> {

    private ModifiableByteArray encryptedChallenge;
    private ModifiableInteger encryptedChallengeBitLenght;

    public ModifiableInteger getEncryptedChallengeBitLenght() {
        return encryptedChallengeBitLenght;
    }

    public void setEncryptedChallengeBitLenght(ModifiableInteger encryptedChallengeBitLenght) {
        this.encryptedChallengeBitLenght = encryptedChallengeBitLenght;
    }

    public void setEncryptedChallengeBitLenght(int identityPublicModulusBitLenght) {
        this.encryptedChallengeBitLenght =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptedChallengeBitLenght, identityPublicModulusBitLenght);
    }

    public ModifiableByteArray getEncryptedChallenge() {
        return encryptedChallenge;
    }

    public void setEncryptedChallenge(ModifiableByteArray encryptedChallenge) {
        this.encryptedChallenge = encryptedChallenge;
    }

    public void setIdentityPublicModulus(byte[] identityPublicModulus) {
        this.encryptedChallenge =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptedChallenge, identityPublicModulus);
    }

    @Override
    public RsaAuthChallengeMessageSSHV1Handler getHandler(SshContext context) {
        return new RsaAuthChallengeMessageSSHV1Handler(context);
    }

    @Override
    public SshMessageParser<RsaAuthChallengeMessageSSH1> getParser(
            SshContext context, InputStream stream) {
        return new RsaAuthChallengeMessageSSHV1Parser(context, stream);
    }

    @Override
    public SshMessagePreparator<RsaAuthChallengeMessageSSH1> getPreparator(SshContext context) {
        return new RsaAuthMessageChallengeSSHV1Preparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<RsaAuthChallengeMessageSSH1> getSerializer(SshContext context) {
        return new RsaAuthChallengeMessageSSHV1Serializier(this);
    }

    @Override
    public String toShortString() {
        return "SSH_CMSG_AUTH_RSA_CHALLENGE";
    }
}
