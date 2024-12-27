/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.authentication.serializer;

import static de.rub.nds.modifiablevariable.util.StringUtil.backslashEscapeString;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.authentication.message.UserAuthPkOkMessage;
import de.rub.nds.sshattacker.core.protocol.common.SerializerStream;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import java.nio.charset.StandardCharsets;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class UserAuthPkOkMessageSerializer extends SshMessageSerializer<UserAuthPkOkMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static void serializePubkeyAlgName(
            UserAuthPkOkMessage object, SerializerStream output) {
        Integer pubkeyAlgNameLength = object.getPubkeyAlgNameLength().getValue();
        LOGGER.debug("Pubkey algorithm name length: {}", pubkeyAlgNameLength);
        output.appendInt(pubkeyAlgNameLength, DataFormatConstants.STRING_SIZE_LENGTH);
        String pubkeyAlgName = object.getPubkeyAlgName().getValue();
        LOGGER.debug("Pubkey algorithm name: {}", () -> backslashEscapeString(pubkeyAlgName));
        output.appendString(pubkeyAlgName, StandardCharsets.US_ASCII);
    }

    private static void serializePubkey(UserAuthPkOkMessage object, SerializerStream output) {
        Integer pubkeyLength = object.getPubkeyLength().getValue();
        LOGGER.debug("Pubkey length: {}", pubkeyLength);
        output.appendInt(pubkeyLength, DataFormatConstants.STRING_SIZE_LENGTH);
        byte[] pubkey = object.getPubkey().getValue();
        LOGGER.debug("Pubkey: {}", () -> ArrayConverter.bytesToRawHexString(pubkey));
        output.appendBytes(pubkey);
    }

    @Override
    protected void serializeMessageSpecificContents(
            UserAuthPkOkMessage object, SerializerStream output) {
        serializePubkeyAlgName(object, output);
        serializePubkey(object, output);
    }
}
