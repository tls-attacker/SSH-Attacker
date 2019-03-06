package de.rub.nds.sshattacker.protocol.layers;

import de.rub.nds.sshattacker.protocol.message.BinaryPacket;
import de.rub.nds.sshattacker.protocol.parser.BinaryPacketParser;
import de.rub.nds.sshattacker.protocol.serializer.BinaryPacketSerializer;
import de.rub.nds.sshattacker.state.SshContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class BinaryPacketLayer {

    private SshContext context;

    private static final Logger LOGGER = LogManager.getLogger();

    // TODO add encryption
    // TODO add decryption
    public List<BinaryPacket> parseBinaryPackets(byte[] raw) {
        List<BinaryPacket> list = new ArrayList<>();
        BinaryPacket packet = new BinaryPacketParser(0, raw).parse();
        list.add(packet);
        return list;
    }

    public byte[] serializeBinaryPackets(List<BinaryPacket> list) {
        ByteArrayOutputStream serialized = new ByteArrayOutputStream();

        for (BinaryPacket packet : list) {
            try {
                serialized.write(new BinaryPacketSerializer(packet).serialize());
            } catch (IOException e) {
                LOGGER.debug("Error while writing to ByteArrayOutputStream " + e.getMessage());
            }
        }
        return serialized.toByteArray();
    }
}
