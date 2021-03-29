package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.IgnoreMessage;
import de.rub.nds.sshattacker.util.Converter;

public class IgnoreMessageSerializer extends MessageSerializer<IgnoreMessage> {

    public IgnoreMessageSerializer(IgnoreMessage msg) {
        super(msg);
    }

    private void serializeData() {
        appendBytes(Converter.stringToLengthPrefixedBinaryString(msg.getData().getValue()));
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializeData();
        return getAlreadySerialized();
    }

}
