package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.protocol.message.RequestFailureMessage;

public class RequestFailureMessageSerializer extends MessageSerializer<RequestFailureMessage> {

    public RequestFailureMessageSerializer(RequestFailureMessage msg) {
        super(msg);
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        return new byte[0];
    }

}
