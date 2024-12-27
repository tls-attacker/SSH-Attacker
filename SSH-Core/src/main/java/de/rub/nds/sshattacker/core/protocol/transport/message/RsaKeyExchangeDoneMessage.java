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
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangeDoneMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;

public class RsaKeyExchangeDoneMessage extends SshMessage<RsaKeyExchangeDoneMessage>
        implements ExchangeHashSignatureMessage {

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

    public RsaKeyExchangeDoneMessage() {
        super();
    }

    public RsaKeyExchangeDoneMessage(RsaKeyExchangeDoneMessage other) {
        super(other);
        signatureLength = other.signatureLength != null ? other.signatureLength.createCopy() : null;
        signature = other.signature != null ? other.signature.createCopy() : null;
    }

    @Override
    public RsaKeyExchangeDoneMessage createCopy() {
        return new RsaKeyExchangeDoneMessage(this);
    }

    @Override
    public ModifiableInteger getSignatureLength() {
        return signatureLength;
    }

    @Override
    public void setSignatureLength(ModifiableInteger signatureLength) {
        this.signatureLength = signatureLength;
    }

    @Override
    public void setSignatureLength(int signatureLength) {
        this.signatureLength =
                ModifiableVariableFactory.safelySetValue(this.signatureLength, signatureLength);
    }

    @Override
    public ModifiableByteArray getSignature() {
        return signature;
    }

    @Override
    public void setSignature(ModifiableByteArray signature) {
        setSignature(signature, false);
    }

    @Override
    public void setSignature(byte[] signature) {
        setSignature(signature, false);
    }

    @Override
    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        this.signature = signature;
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    @Override
    public void setSignature(byte[] signature, boolean adjustLengthField) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        if (adjustLengthField) {
            setSignatureLength(this.signature.getValue().length);
        }
    }

    public void setSoftlySignature(byte[] signature, boolean adjustLengthField, Config config) {
        if (config.getAlwaysPrepareKex()
                || this.signature == null
                || this.signature.getOriginalValue() == null) {
            this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        }
        if (adjustLengthField) {
            if (config.getAlwaysPrepareLengthFields()
                    || signatureLength == null
                    || signatureLength.getOriginalValue() == null) {
                setSignatureLength(this.signature.getValue().length);
            }
        }
    }

    @Override
    public RsaKeyExchangeDoneMessageHandler getHandler(SshContext context) {
        return new RsaKeyExchangeDoneMessageHandler(context, this);
    }

    @Override
    public void prepare(Chooser chooser) {
        RsaKeyExchangeDoneMessageHandler.PREPARATOR.prepare(this, chooser);
    }

    @Override
    public byte[] serialize() {
        return RsaKeyExchangeDoneMessageHandler.SERIALIZER.serialize(this);
    }
}
