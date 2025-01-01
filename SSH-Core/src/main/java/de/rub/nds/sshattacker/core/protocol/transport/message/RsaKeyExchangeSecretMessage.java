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
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangeSecretMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class RsaKeyExchangeSecretMessage extends SshMessage<RsaKeyExchangeSecretMessage> {

    private ModifiableInteger encryptedSecretLength;
    private ModifiableByteArray encryptedSecret;

    public RsaKeyExchangeSecretMessage() {
        super();
    }

    public RsaKeyExchangeSecretMessage(RsaKeyExchangeSecretMessage other) {
        super(other);
        encryptedSecretLength =
                other.encryptedSecretLength != null
                        ? other.encryptedSecretLength.createCopy()
                        : null;
        encryptedSecret = other.encryptedSecret != null ? other.encryptedSecret.createCopy() : null;
    }

    @Override
    public RsaKeyExchangeSecretMessage createCopy() {
        return new RsaKeyExchangeSecretMessage(this);
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

    public void setSoftlyEncryptedSecret(
            byte[] encryptedSecret, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.encryptedSecret == null
                || this.encryptedSecret.getOriginalValue() == null) {
            this.encryptedSecret =
                    ModifiableVariableFactory.safelySetValue(this.encryptedSecret, encryptedSecret);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || encryptedSecretLength == null
                    || encryptedSecretLength.getOriginalValue() == null) {
                setEncryptedSecretLength(this.encryptedSecret.getValue().length);
            }
        }
    }

    public static final RsaKeyExchangeSecretMessageHandler HANDLER =
            new RsaKeyExchangeSecretMessageHandler();

    @Override
    public RsaKeyExchangeSecretMessageHandler getHandler() {
        return HANDLER;
    }

    @Override
    public void adjustContext(SshContext context) {
        HANDLER.adjustContext(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        RsaKeyExchangeSecretMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return RsaKeyExchangeSecretMessageHandler.SERIALIZER.serialize(this);
    }
}
