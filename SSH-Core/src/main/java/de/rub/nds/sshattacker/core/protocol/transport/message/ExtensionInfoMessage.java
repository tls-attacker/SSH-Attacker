package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessage;
import de.rub.nds.sshattacker.core.protocol.transport.handler.ExtensionInfoMessageHandler;
import de.rub.nds.sshattacker.core.state.SshContext;

import java.util.ArrayList;

/* Class for SSH_MSG_EXT_INFO message

   structure:   byte            SSH_MSG_EXT_INFO(value 7)
                uint32          nr_extensions
                repeat the following 2 fields "nr-extensions" times:
                    string      extension-name
                    string      extension-value

  NOTE:         uint32 := 4 byte unsigned integer
                string := 4 byte length | string/byte array
*/

public class ExtensionInfoMessage extends SshMessage<ExtensionInfoMessage> {


    public static final MessageIdConstant ID = MessageIdConstant.SSH_MSG_EXT_INFO;

    private ModifiableByteArray numberExtensions;

    private ArrayList<Extension> extensions = new ArrayList<Extension>();


    public void setNumberExtensions(byte[] count) {
        this.numberExtensions.setOriginalValue(count);
    }

    public ModifiableByteArray getNumberExtensions() {
        return this.numberExtensions;
    }

    public void setExtensions(ArrayList<Extension> list) {
        this.extensions = new ArrayList<Extension>(list);
    }

    public ArrayList<Extension> getExtensions() {
        return this.extensions;
    }

    public ExtensionInfoMessageHandler getHandler(SshContext context) {
        return new ExtensionInfoMessageHandler(context, this);
    }
}
