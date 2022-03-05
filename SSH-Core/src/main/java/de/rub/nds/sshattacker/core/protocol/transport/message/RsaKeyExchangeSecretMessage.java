/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.MessageIDConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangeSecretMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

public class RsaKeyExchangeSecretMessage extends SshMessage<RsaKeyExchangeSecretMessage> {

    private ModifiableInteger encryptedSecretLength;
    private ModifiableByteArray encryptedSecret;

    public RsaKeyExchangeSecretMessage() {
        super(MessageIDConstant.SSH_MSG_KEXRSA_SECRET);
    }

    public ModifiableInteger getEncryptedSecretLength() {
        return encryptedSecretLength;
    }

    public void setEncryptedSecretLength(ModifiableInteger encryptedSecretLength) {
        this.encryptedSecretLength = encryptedSecretLength;
    }

    public void setEncryptedSecretLength(int encryptedSecretLength) {
        this.encryptedSecretLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encryptedSecretLength, encryptedSecretLength);
    }

    public ModifiableByteArray getEncryptedSecret() {
        return encryptedSecret;
    }

    public void setEncryptedSecret(byte[] encryptedSecret) {
        setEncryptedSecret(encryptedSecret, false);
    }

    public void setEncryptedSecret(ModifiableByteArray encryptedSecret, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEncryptedSecretLength(encryptedSecret.getValue().length);
        }
        this.encryptedSecret = encryptedSecret;
    }

    public void setEncryptedSecret(byte[] encryptedSecret, boolean adjustLengthField) {
        if (adjustLengthField) {
            setEncryptedSecretLength(encryptedSecret.length);
        }
        this.encryptedSecret =
                ModifiableVariableFactory.safelySetValue(this.encryptedSecret, encryptedSecret);
    }

    @Override
    public SshMessageHandler<RsaKeyExchangeSecretMessage> getHandler(SshContext context) {
        return new RsaKeyExchangeSecretMessageHandler(context, this);
    }
}
