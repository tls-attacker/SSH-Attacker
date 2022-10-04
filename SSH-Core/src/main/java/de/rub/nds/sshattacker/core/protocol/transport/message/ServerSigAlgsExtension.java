package de.rub.nds.sshattacker.core.protocol.transport.message;

import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.core.constants.ExtensionNameConstants;
import de.rub.nds.sshattacker.core.util.Converter;

/* class for "server-sig-algs"-extension sent by server
   structure:   extension-name          string          "server-sig-algs"
                extension-value         name-list       public_key_algorithms_accepted

   NOTE:        name-list := string containing a comma-separated list of names
                             (4 byte length field followed by a comma-separated list of zero or more names)

   This extension is sent by a server and contains a list of all public key algorithms the server can process for
   public key authentification
*/

public class ServerSigAlgsExtension extends Extension {

    public ServerSigAlgsExtension(ModifiableString name, ModifiableString value) {
        super(name, value);
    }

    public ServerSigAlgsExtension(ModifiableString value) {
        super(Converter.stringToModifiableString(ExtensionNameConstants.SERVER_SIG_ALGS), value);
    }

}
