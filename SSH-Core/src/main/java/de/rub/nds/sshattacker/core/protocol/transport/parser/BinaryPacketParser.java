/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * <p>Copyright 2014-2021 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * <p>Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
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
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketParser extends Parser<BinaryPacket> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final SshContext context;
    private final BinaryPacket resultingPacket = new BinaryPacket();

    public BinaryPacketParser(byte[] array, int startPosition, SshContext context) {
        super(array, startPosition);
        this.context = context;
    }

    private void parsePacketLength() {
        ModifiableInteger packetLength =
                ModifiableVariableFactory.safelySetValue(
                        null, parseIntField(BinaryPacketConstants.LENGTH_FIELD_LENGTH));
        LOGGER.debug("Packet Length: " + packetLength.getValue());
        resultingPacket.setPacketLength(packetLength);
    }

    private void parsePaddingLength() {
        ModifiableByte paddingLength =
                ModifiableVariableFactory.safelySetValue(
                        null, parseByteField(BinaryPacketConstants.PADDING_FIELD_LENGTH));
        LOGGER.debug("Padding Length: " + paddingLength.getValue());
        resultingPacket.setPaddingLength(paddingLength);
    }

    private void parsePayload() {
        int payloadSize =
                resultingPacket.getPacketLength().getValue()
                        - resultingPacket.getPaddingLength().getValue()
                        - BinaryPacketConstants.PADDING_FIELD_LENGTH;
        LOGGER.debug("Payload Size: " + payloadSize);
        ModifiableByteArray payload =
                ModifiableVariableFactory.safelySetValue(null, parseByteArrayField(payloadSize));
        LOGGER.debug("Payload: " + payload);
        resultingPacket.setPayload(payload);
    }

    private void parsePadding() {
        ModifiableByteArray padding =
                ModifiableVariableFactory.safelySetValue(
                        null, parseByteArrayField(resultingPacket.getPaddingLength().getValue()));
        LOGGER.debug("Padding: " + padding);
        resultingPacket.setPadding(padding);
    }

    private void parseMAC() {
        MacAlgorithm macAlgorithm =
                (context.isClient()
                                ? context.getMacAlgorithmServerToClient()
                                : context.getMacAlgorithmClientToServer())
                        .orElse(null);
        if (macAlgorithm == null
                || macAlgorithm.getOutputSize() == 0
                || !context.getKeyExchangeInstance().isPresent()
                || !context.getKeyExchangeInstance().get().isComplete()) {
            LOGGER.debug("MAC: none");
            resultingPacket.setMac(new byte[] {});
        } else {
            ModifiableByteArray mac =
                    ModifiableVariableFactory.safelySetValue(
                            null, parseArrayOrTillEnd(macAlgorithm.getOutputSize()));
            LOGGER.debug("MAC: " + mac);
            resultingPacket.setMac(mac);
        }
    }

    @Override
    public BinaryPacket parse() {
        parsePacketLength();
        parsePaddingLength();
        parsePayload();
        parsePadding();
        parseMAC();
        return resultingPacket;
    }

    public static List<BinaryPacket> parseAll(byte[] array, SshContext context) {
        List<BinaryPacket> list = new ArrayList<>();
        int pointer = 0;
        while (array.length - pointer > BinaryPacketConstants.LENGTH_FIELD_LENGTH) {
            BinaryPacket packet = new BinaryPacketParser(array, pointer, context).parse();
            // Advance pointer to point to the next packet (if any) by adding the packet length to
            // the pointer
            pointer +=
                    BinaryPacketConstants.LENGTH_FIELD_LENGTH
                            + packet.getPacketLength().getOriginalValue()
                            + packet.getMac().getOriginalValue().length;
            list.add(packet);
        }
        return list;
    }
}
