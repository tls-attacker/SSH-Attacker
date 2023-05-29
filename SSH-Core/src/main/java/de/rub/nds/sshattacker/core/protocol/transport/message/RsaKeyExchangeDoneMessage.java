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
import de.rub.nds.sshattacker.core.protocol.transport.handler.RsaKeyExchangeDoneMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.RsaKeyExchangeDoneMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.RsaKeyExchangeDoneMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.RsaKeyExchangeDoneMessageSerializer;
import java.io.InputStream;

public class RsaKeyExchangeDoneMessage extends SshMessage<RsaKeyExchangeDoneMessage>
        implements ExchangeHashSignatureMessage {

    private ModifiableInteger signatureLength;
    private ModifiableByteArray signature;

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
        this.setSignature(signature, false);
    }

    @Override
    public void setSignature(byte[] signature) {
        this.setSignature(signature, false);
    }

    @Override
    public void setSignature(ModifiableByteArray signature, boolean adjustLengthField) {
        this.signature = signature;
        if (adjustLengthField) {
            this.setSignatureLength(this.signature.getValue().length);
        }
    }

    @Override
    public void setSignature(byte[] signature, boolean adjustLengthField) {
        this.signature = ModifiableVariableFactory.safelySetValue(this.signature, signature);
        if (adjustLengthField) {
            this.setSignatureLength(this.signature.getValue().length);
        }
    }

    @Override
    public SshMessageHandler<RsaKeyExchangeDoneMessage> getHandler(SshContext context) {
        return new RsaKeyExchangeDoneMessageHandler(context);
    }

    @Override
    public SshMessageParser<RsaKeyExchangeDoneMessage> getParser(
            SshContext context, InputStream stream) {
        return new RsaKeyExchangeDoneMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<RsaKeyExchangeDoneMessage> getPreparator(SshContext context) {
        return new RsaKeyExchangeDoneMessagePreparator(context.getChooser(), this);
    }

    @Override
    public SshMessageSerializer<RsaKeyExchangeDoneMessage> getSerializer(SshContext context) {
        return new RsaKeyExchangeDoneMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "RSA_KEX_DONE";
    }
}
