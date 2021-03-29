/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.util.Converter;

public class ChannelOpenFailureMessageSerializer extends MessageSerializer<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessageSerializer(ChannelOpenFailureMessage msg) {
        super(msg);
    }

    private void serializeRecipientChannel() {
        appendInt(msg.getRecipientChannel().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeReasonCode() {
        appendInt(msg.getReasonCode().getValue(), DataFormatConstants.INT32_SIZE);
    }

    private void serializeReason() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getReason().getValue()));
    }

    private void serializeLanguageTag() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getLanguageTag().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeRecipientChannel();
        serializeReasonCode();
        serializeReason();
        serializeLanguageTag();
        return getAlreadySerialized();
    }

}
