package de.rub.nds.sshattacker.protocol.serializer;

import de.rub.nds.sshattacker.constants.DataFormatConstants;
import de.rub.nds.sshattacker.protocol.message.UserAuthFailureMessage;

public class UserAuthFailureMessageSerializer extends MessageSerializer<UserAuthFailureMessage> {

    public UserAuthFailureMessageSerializer(UserAuthFailureMessage msg) {
        super(msg);
    }

    private void serializePossibleAuthenticationMethodslLength() {
        appendInt(msg.getPossibleAuthenticationMethodsLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
    }

    private void serializePossibleAuthenticationMethods() {
        appendString(msg.getPossibleAuthenticationMethods().getValue());
    }

    private void serializePartialSuccess() {
        appendByte(msg.getPartialSuccess().getValue());
    }

    @Override
    protected byte[] serializeMessageSpecificPayload() {
        serializePossibleAuthenticationMethodslLength();
        serializePossibleAuthenticationMethods();
        serializePartialSuccess();
        return getAlreadySerialized();
    }

}
