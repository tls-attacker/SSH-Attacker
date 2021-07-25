/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.sshattacker.core.constants.BinaryPacketConstants;
import de.rub.nds.sshattacker.core.constants.MacAlgorithm;
import de.rub.nds.sshattacker.core.protocol.common.Parser;
import de.rub.nds.sshattacker.core.protocol.transport.message.BinaryPacket;

import java.util.ArrayList;
import java.util.List;

import de.rub.nds.sshattacker.core.state.SshContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketParser extends Parser<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final SshContext context;

    public BinaryPacketParser(int startPosition, byte[] array, SshContext context) {
        super(startPosition, array);
        this.context = context;
    }

    private void parsePacketLength(BinaryPacket msg) {
        ModifiableInteger packetLength = ModifiableVariableFactory.safelySetValue(null,
                parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Packet Length: " + packetLength.getValue());
        msg.setPacketLength(packetLength);
    }

    private void parsePaddingLength(BinaryPacket msg) {
        ModifiableByte paddingLength = ModifiableVariableFactory.safelySetValue(null,
                parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        LOGGER.debug("Padding Length: " + paddingLength.getValue());
        msg.setPaddingLength(paddingLength);
    }

    private void parsePayload(BinaryPacket msg) {
        int payloadSize = msg.getPacketLength().getValue() - msg.getPaddingLength().getValue()
                - BinaryPacketConstants.PADDING_FIELD_LENGTH;
        LOGGER.debug("Payload Size: " + payloadSize);
        ModifiableByteArray payload = ModifiableVariableFactory.safelySetValue(null, parseByteArrayField(payloadSize));
        LOGGER.debug("Payload: " + payload);
        msg.setPayload(payload);
    }

    private void parsePadding(BinaryPacket msg) {
        ModifiableByteArray padding = ModifiableVariableFactory.safelySetValue(null, parseByteArrayField(msg
                .getPaddingLength().getValue()));
        LOGGER.debug("Padding: " + padding);
        msg.setPadding(padding);
    }

    private void parseMAC(BinaryPacket msg) {
        MacAlgorithm macAlgorithm = (context.isClient() ? context.getMacAlgorithmServerToClient() : context
                .getMacAlgorithmClientToServer()).orElse(null);
        if (macAlgorithm == null || macAlgorithm.getOutputSize() == 0 || !context.getKeyExchangeInstance().isPresent()
                || !context.getKeyExchangeInstance().get().isComplete()) {
            LOGGER.debug("MAC: none");
            msg.setMac(new byte[] {});
        } else {
            ModifiableByteArray mac = ModifiableVariableFactory.safelySetValue(null,
                    parseArrayOrTillEnd(macAlgorithm.getOutputSize()));
            LOGGER.debug("MAC: " + mac);
            msg.setMac(mac);
        }

    }

    @Override
    public BinaryPacket parse() {
        BinaryPacket msg = new BinaryPacket();
        parsePacketLength(msg);
        parsePaddingLength(msg);
        parsePayload(msg);
        parsePadding(msg);
        parseMAC(msg);
        return msg;
    }

    public List<BinaryPacket> parseAll() {
        List<BinaryPacket> list = new ArrayList<>();
        while (getBytesLeft() >= BinaryPacketConstants.LENGTH_FIELD_LENGTH) {
            list.add(parse());
        }
        return list;
    }
}
