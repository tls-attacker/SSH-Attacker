package de.rub.nds.sshattacker.core.protocol.transport.parser;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageParser;
import de.rub.nds.sshattacker.core.util.Converter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import de.rub.nds.sshattacker.core.protocol.transport.message.Extension;

public class ExtensionInfoMessageParser extends SshMessageParser<ExtensionInfoMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ExtensionInfoMessageParser(byte[] array) {
        super(array);
    }

    public ExtensionInfoMessageParser(byte[] array, int startPosition) {
        super(array, startPosition);
    }

    @Override
    public ExtensionInfoMessage createMessage() {
        return new ExtensionInfoMessage();
    }

    @Override
    public void parseMessageSpecificContents() {
        parseNumberExtensions();
        parseExtensions();
    }

    private void parseNumberExtensions() {
        byte[] count = super.parseByteArrayField(DataFormatConstants.UINT32_SIZE);
        message.setNumberExtensions(count);
        LOGGER.debug("Number of Extensions: " + ByteBuffer.wrap(message.getNumberExtensions().getValue()).getInt());
    }

    private void parseExtensions() {
        int count = ByteBuffer.wrap(message.getNumberExtensions().getValue()).getInt();
        ArrayList<Extension> list = new ArrayList<Extension>();

        for(int i = 0; i < count; i++) {
            // string := 4 byte unsigned integer | string/byte array

            // parse extension name
            byte[] lengthExtensionName = super.parseByteArrayField(DataFormatConstants.UINT32_SIZE);
            int lengthOfExtensionName = ByteBuffer.wrap(lengthExtensionName).getInt();
            byte[] extensionName = super.parseByteArrayField(lengthOfExtensionName);

            // parse extension value
            byte[] lengthExtensionValue = super.parseByteArrayField(DataFormatConstants.UINT32_SIZE);
            int lengthOfExtensionValue = ByteBuffer.wrap(lengthExtensionValue).getInt();
            byte[] extensionValue = super.parseByteArrayField(lengthOfExtensionValue);

            // convert byte[] into strings for constructor
            ModifiableString name = Converter.byteArrayToModifiableString(extensionName);
            ModifiableString value = Converter.byteArrayToModifiableString(extensionValue);

            Extension extension = new Extension(name, value);
            extension.setExtensionNameLengthInBytes(lengthOfExtensionName);
            extension.setExtensionValueLengthInBytes(lengthOfExtensionValue);
            list.add(extension);
        }

        message.setExtensions(list);
        LOGGER.debug("Extensions: " + message.getExtensions());
    }

}
