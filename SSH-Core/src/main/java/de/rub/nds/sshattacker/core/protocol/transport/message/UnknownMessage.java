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
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.handler.UnknownMessageHandler;
import de.rub.nds.sshattacker.core.protocol.transport.parser.UnknownMessageParser;
import de.rub.nds.sshattacker.core.protocol.transport.preparator.UnknownMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.transport.serializer.UnknownMessageSerializer;
import java.io.InputStream;

public class UnknownMessage extends SshMessage<UnknownMessage> {

    private ModifiableByteArray payload;

    public ModifiableByteArray getPayload() {
        return payload;
    }

    public void setPayload(ModifiableByteArray payload) {
        this.payload = payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = ModifiableVariableFactory.safelySetValue(this.payload, payload);
    }

    @Override
    public String toCompactString() {
        if (messageId != null && messageId.getValue() != null) {
            return "UnknownMessage (" + MessageIdConstant.getNameById(messageId.getValue()) + ")";
        }
        return "UnknownMessage (no id set)";
    }

    @Override
    public UnknownMessageHandler getHandler(SshContext context) {
        return new UnknownMessageHandler(context);
    }

    @Override
    public UnknownMessageParser getParser(SshContext context, InputStream stream) {
        return new UnknownMessageParser(stream);
    }

    @Override
    public SshMessagePreparator<UnknownMessage> getPreparator(SshContext context) {
        return new UnknownMessagePreparator(context.getChooser(), this);
    }

    @Override
    public UnknownMessageSerializer getSerializer(SshContext context) {
        return new UnknownMessageSerializer(this);
    }

    @Override
    public String toShortString() {
        return "UNKNOW_MESSAEG";
    }
}
