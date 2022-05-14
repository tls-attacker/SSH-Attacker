package de.rub.nds.sshattacker.core.protocol.authentication.parser;

import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;

public class UserAuthPkOkMessageParser extends SshMessageParser<UserAuthPkOkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public UserAuthPkOkMessageParser(byte[] array) { super(array); }

    public UserAuthPkOkMessageParser(byte[] array, int startPosition) { super(array, startPosition); }

    @Override
    protected UserAuthPkOkMessage createMessage() { return new UserAuthPkOkMessage(); }

    private void parsePubkey() {
        message.setPubkeyLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Pubkey length: " + message.getPubkeyLength().getValue());
        message.setPubkey(parseByteString(message.getPubkeyLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Pubkey: " + message.getPubkey().getValue());
    }

    private void parsePubkeyAlgName() {
        message.setPubkeyAlgNameLength(parseIntField(DataFormatConstants.STRING_SIZE_LENGTH));
        LOGGER.debug("Pubkey algorithm name length: " + message.getPubkeyAlgNameLength().getValue());
        message.setPubkeyAlgName(parseByteString(message.getPubkeyAlgNameLength().getValue(), StandardCharsets.US_ASCII));
        LOGGER.debug("Pubkey algorithm name: " + message.getPubkeyAlgName().getValue());
    }

    @Override
    protected void parseMessageSpecificContents() {
        parsePubkeyAlgName();
        parsePubkey();
    }
}
