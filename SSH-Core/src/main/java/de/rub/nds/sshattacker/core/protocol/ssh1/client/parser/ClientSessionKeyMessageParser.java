/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.ssh1.client.parser;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.*;
import de.rub.nds.sshattacker.core.layer.context.SshContext;
import de.rub.nds.sshattacker.core.protocol.common.Ssh1MessageParser;
import de.rub.nds.sshattacker.core.protocol.ssh1.client.message.ClientSessionKeyMessage;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ClientSessionKeyMessageParser extends Ssh1MessageParser<ClientSessionKeyMessage> {
    private static final Logger LOGGER = LogManager.getLogger();

    public ClientSessionKeyMessageParser(SshContext context, InputStream stream) {
        super(stream);
    }

    private void parseChosenCipherMethod(ClientSessionKeyMessage message) {
        CipherMethod chosenCipherMethod = CipherMethod.fromId(parseIntField(1));
        message.setChosenCipherMethod(chosenCipherMethod);
        LOGGER.debug("Ciphermethod: {}", chosenCipherMethod);
    }

    private void parseAntiSpoofingCookie(ClientSessionKeyMessage message) {
        message.setAntiSpoofingCookie(parseByteArrayField(8));
        LOGGER.debug("AntiSpoofingCookie: {}", message.getAntiSpoofingCookie().getValue());
    }

    private void parseSessionKey(ClientSessionKeyMessage message) {
        // message.setEncryptedSessioKey(parseMultiprecisionAsByteArray());
        message.setEncryptedSessioKey(parseMultiprecision().toByteArray());
        LOGGER.debug(
                "Encrypted Session Key: {}",
                ArrayConverter.bytesToHexString(message.getEncryptedSessioKey().getValue()));
    }

    private void parseProtocolFlags(ClientSessionKeyMessage message) {
        message.setProtocolFlagMask(parseIntField(4));
        LOGGER.debug("Protocol Flags Mask {}", message.getProtocolFlagMask().getValue());

        int flagMask = message.getProtocolFlagMask().getValue();
        String stringProtocolMask = Integer.toBinaryString(flagMask);
        List<ProtocolFlag> chosenProtocolFlags = new ArrayList<>();
        for (int i = 0; i < stringProtocolMask.length(); i++) {
            if (stringProtocolMask.charAt(i) == '1') {
                int id = stringProtocolMask.length() - 1 - i;
                chosenProtocolFlags.add(ProtocolFlag.fromId(id));
                LOGGER.debug("Parsed ProtocolFlags {} at id {}", ProtocolFlag.fromId(id), id);
            }
        }

        message.setChosenProtocolFlags(chosenProtocolFlags);
    }

    @Override
    protected void parseMessageSpecificContents(ClientSessionKeyMessage message) {
        parseChosenCipherMethod(message);
        parseAntiSpoofingCookie(message);
        parseSessionKey(message);
        parseProtocolFlags(message);
    }

    @Override
    public void parse(ClientSessionKeyMessage message) {
        parseProtocolMessageContents(message);
    }
}
