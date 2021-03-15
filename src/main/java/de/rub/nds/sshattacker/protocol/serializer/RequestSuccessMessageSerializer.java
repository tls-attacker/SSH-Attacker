package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.RequestSuccessMessage;

public class RequestSuccessMessageSerializer extends MessageSerializer<RequestSuccessMessage> {

    public RequestSuccessMessageSerializer(RequestSuccessMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        appendBytes(msg.getPayload().getValue());
        return getAlreadySerialized();
    }

}
