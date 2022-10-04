package de.rub.nds.sshattacker.core.protocol.transport.serializer;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.protocol.common.SshMessageSerializer;
import de.rub.nds.sshattacker.core.protocol.transport.message.Extension;
import de.rub.nds.sshattacker.core.protocol.transport.message.ExtensionInfoMessage;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

/* Class for serializing an SSH_MSG_EXT_INFO message

   structure:   byte            SSH_MSG_EXT_INFO(value 7)
                uint32          nr_extensions
                repeat the following 2 fields "nr-extensions" times:
                    string      extension-name
                    string      extension-value

  NOTE:         uint32 := 4 byte unsigned integer
                string := 4 byte length | string/byte array
*/

public class ExtensionInfoMessageSerializer extends SshMessageSerializer<ExtensionInfoMessage> {


    private static final Logger LOGGER = LogManager.getLogger();

    public ExtensionInfoMessageSerializer(ExtensionInfoMessage message) {
        super(message);
    }

    private void serializeNumberExtension() {
        LOGGER.debug("Number of Extension: " + message.getNumberExtensions());
        appendBytes(message.getNumberExtensions().getValue());
    }

    private void serializeExtensions() {
        LOGGER.debug("Extensions: " + message.getExtensions());

        int numberExtensions = new BigInteger(message.getNumberExtensions().getValue()).intValue();
        ArrayList<Extension> extensions = message.getExtensions();

        for(int i = 0; i < numberExtensions; i++) {
            Extension extension = extensions.get(i);
            ModifiableString extensionName = extension.getExtensionName();
            ModifiableString extensionValue = extension.getExtensionValue();

            // append 4 byte unsigned integer length followed by extensionName
            appendInt(extension.getExtensionNameLengthInBytes(), DataFormatConstants.UINT32_SIZE);
            appendString(extensionName.getValue(), StandardCharsets.US_ASCII);

            //append 4 byte unsigned integer length followed by extensionValue
            appendInt(extension.getExtensionValueLengthInBytes(), DataFormatConstants.UINT32_SIZE);
            appendString(extensionValue.getValue(), StandardCharsets.US_ASCII);
        }
    }



    @Override
    public void serializeMessageSpecificContents() {
        serializeNumberExtension();
        serializeExtensions();
    }

}
