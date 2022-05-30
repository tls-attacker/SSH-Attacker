package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPubkeyMessage;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.nio.charset.StandardCharsets;

public class UserAuthPubkeyMessageSerializer extends UserAuthRequestMessageSerializer<UserAuthPubkeyMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPubkeyMessageSerializer(UserAuthPubkeyMessage message) {
        super(message);
    }

    private void serializeUseSignature() {
        LOGGER.debug("Use Signature: " + Converter.byteToBoolean(message.getUseSignature().getValue()));
        appendByte(message.getUseSignature().getValue());
    }

    private void serializePubkeyAlgName() {
        LOGGER.debug("Pubkey algorithm name length: " + message.getPubkeyAlgNameLength().getValue());
        appendInt(message.getPubkeyAlgNameLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Pubkey algorithm name: " + message.getPubkeyAlgName().getValue());
        appendString(message.getPubkeyAlgName().getValue(), StandardCharsets.US_ASCII);
    }
    private void serializePubkey() {
        LOGGER.debug("Pubkey length: " + message.getPubkeyLength().getValue());
        appendInt(message.getPubkeyLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Pubkey: " + new String(message.getPubkey().getValue()));
        appendBytes(message.getPubkey().getValue());
    }

    private void serializeSignature() {
        LOGGER.debug("Signature length: " + message.getSignatureLength().getValue());
        appendInt(message.getSignatureLength().getValue(), DataFormatConstants.STRING_SIZE_LENGTH);
        LOGGER.debug("Signature: " + new String(message.getSignature().getValue()));
        appendBytes(message.getSignature().getValue());
    }

    @Override
    public void serializeMessageSpecificContents() {
        super.serializeMessageSpecificContents();
        serializeUseSignature();
        serializePubkeyAlgName();
        serializePubkey();
        if (Converter.byteToBoolean(message.getUseSignature().getValue())) {
            serializeSignature();
        }
    }
}