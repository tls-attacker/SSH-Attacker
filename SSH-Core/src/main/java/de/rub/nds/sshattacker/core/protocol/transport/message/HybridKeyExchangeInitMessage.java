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
import de.rub.nds.sshattacker.core.crypto.kex.HybridKeyExchange;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.handler.HybridKeyExchangeInitMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.HybridKeyExchangeInitMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.HybridKeyExchangeInitMessagePreperator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.HybridKeyExchangeInitMessageSerializer;
import java.io.InputStream;

public class HybridKeyExchangeInitMessage extends SshMessage<HybridKeyExchangeInitMessage> {

    private ModifiableInteger agreementPublicKeyLength;
    private ModifiableByteArray agreementPublicKey;
    private ModifiableInteger encapsulationPublicKeyLength;
    private ModifiableByteArray encapsulationPublicKey;

    public ModifiableInteger getAgreementPublicKeyLength() {
        return agreementPublicKeyLength;
    }

    public void setAgreementPublicKeyLength(ModifiableInteger agreementPublicKeyLength) {
        this.agreementPublicKeyLength = agreementPublicKeyLength;
    }

    public void setAgreementPublicKeyLength(int agreementPublicKeyLength) {
        this.agreementPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.agreementPublicKeyLength, agreementPublicKeyLength);
    }

    public ModifiableByteArray getAgreementPublicKey() {
        return agreementPublicKey;
    }

    public void setAgreementPublicKey(ModifiableByteArray agreementPublicKey) {
        setAgreementPublicKey(agreementPublicKey, false);
    }

    public void setAgreementPublicKey(byte[] agreementPublicKey) {
        setAgreementPublicKey(agreementPublicKey, false);
    }

    public void setAgreementPublicKey(
            ModifiableByteArray agreementPublicKey, boolean adjustLengthField) {
        this.agreementPublicKey = agreementPublicKey;
        if (adjustLengthField) {
            setAgreementPublicKeyLength(this.agreementPublicKey.getValue().length);
        }
    }

    public void setAgreementPublicKey(byte[] agreementPublicKey, boolean adjustLengthField) {
        this.agreementPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.agreementPublicKey, agreementPublicKey);
        if (adjustLengthField) {
            setAgreementPublicKeyLength(this.agreementPublicKey.getValue().length);
        }
    }

    public ModifiableInteger getEncapsulationPublicKeyLength() {
        return encapsulationPublicKeyLength;
    }

    public void setEncapsulationPublicKeyLength(ModifiableInteger encapsulationPublicKeyLength) {
        this.encapsulationPublicKeyLength = encapsulationPublicKeyLength;
    }

    public void setEncapsulationPublicKeyLength(int encapsulationPublicKeyLength) {
        this.encapsulationPublicKeyLength =
                ModifiableVariableFactory.safelySetValue(
                        this.encapsulationPublicKeyLength, encapsulationPublicKeyLength);
    }

    public ModifiableByteArray getEncapsulationPublicKey() {
        return encapsulationPublicKey;
    }

    public void setEncapsulationPublicKey(ModifiableByteArray encapsulationPublicKey) {
        setEncapsulationPublicKey(encapsulationPublicKey, false);
    }

    public void setEncapsulationPublicKey(byte[] encapsulationPublicKey) {
        setEncapsulationPublicKey(encapsulationPublicKey, false);
    }

    public void setEncapsulationPublicKey(
            ModifiableByteArray encapsulationPublicKey, boolean adjustLengthField) {
        this.encapsulationPublicKey = encapsulationPublicKey;
        if (adjustLengthField) {
            setEncapsulationPublicKeyLength(this.encapsulationPublicKey.getValue().length);
        }
    }

    public void setEncapsulationPublicKey(
            byte[] encapsulationPublicKey, boolean adjustLengthField) {
        this.encapsulationPublicKey =
                ModifiableVariableFactory.safelySetValue(
                        this.encapsulationPublicKey, encapsulationPublicKey);
        if (adjustLengthField) {
            setEncapsulationPublicKeyLength(this.encapsulationPublicKey.getValue().length);
        }
    }

    @Override
    public SshMessageHandler<HybridKeyExchangeInitMessage> getHandler(SshContext context) {
        return new HybridKeyExchangeInitMessageHandler(context);
    }

    /*@Override
    public HybridKeyExchangeInitMessageParser getParser(SshContext context, InputStream stream) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(
                array,
                kex.getCombiner(),
                kex.getPkAgreementLength(),
                kex.getPkEncapsulationLength());
    }*/

    @Override
    public HybridKeyExchangeInitMessageParser getParser(SshContext context, InputStream stream) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageParser(context, stream);
    }

    @Override
    public HybridKeyExchangeInitMessagePreperator getPreparator(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessagePreperator(
                context.getChooser(), this, kex.getCombiner());
    }

    @Override
    public HybridKeyExchangeInitMessageSerializer getSerializer(SshContext context) {
        HybridKeyExchange kex = context.getChooser().getHybridKeyExchange();
        return new HybridKeyExchangeInitMessageSerializer(this, kex.getCombiner());
    }

    @Override
    public String toShortString() {
        return "HYB_KEY_EXCHANGE";
    }
}
