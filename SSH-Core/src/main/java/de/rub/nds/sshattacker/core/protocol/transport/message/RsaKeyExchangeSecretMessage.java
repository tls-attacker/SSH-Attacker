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
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.*;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangeSecretMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangeSecretMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.RsaKeyExchangeSecretMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangeSecretMessageSerializer;
import java.io.InputStream;

public class RsaKeyExchangeSecretMessage extends SshMessage<RsaKeyExchangeSecretMessage> {

    private ModifiableInteger encryptedSecretLength;
    private ModifiableByteArray encryptedSecret;

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
        this.encryptedSecret = encryptedSecret;
        if (adjustLengthField) {
            setEncryptedSecretLength(this.encryptedSecret.getValue().length);
        }
    }

    public void setEncryptedSecret(byte[] encryptedSecret, boolean adjustLengthField) {
        this.encryptedSecret =
                ModifiableVariableFactory.safelySetValue(this.encryptedSecret, encryptedSecret);
        if (adjustLengthField) {
            setEncryptedSecretLength(this.encryptedSecret.getValue().length);
        }
    }

    @Override
    public SshMessageHandler<RsaKeyExchangeSecretMessage> getHandler(SshContext context) {
        return new RsaKeyExchangeSecretMessageHandler(context);
    }

    @Override
    public SshMessageParser<RsaKeyExchangeSecretMessage> getParser(
            SshContext context, InputStream stream) {
        return new RsaKeyExchangeSecretMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangeSecretMessage> getPreparator(SshContext context) {
        return new RsaKeyExchangeSecretMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangeSecretMessage> getSerializer(SshContext context) {
        return new RsaKeyExchangeSecretMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "RSA_KEX_SECRET";
    }
}
