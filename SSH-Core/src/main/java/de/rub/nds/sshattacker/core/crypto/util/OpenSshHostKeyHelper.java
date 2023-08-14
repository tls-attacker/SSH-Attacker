/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2023 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.crypto.util;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey;
import de.rub.nds.sshattacker.core.util.Converter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class OpenSshHostKeyHelper {

    /**
     * Encodes a list of keys into a host key blob value, consisting of one length-prefixed string
     * per key.
     *
     * @param keys the list of keys to encode
     * @return the encoded key blob
     */
    public static byte[] encodeKeys(List<SshPublicKey<?, ?>> keys) {
        return keys.stream()
                .map(PublicKeyHelper::encode)
                .map(Converter::bytesToLengthPrefixedBinaryString)
                .reduce(ArrayConverter::concatenate)
                .orElseGet(() -> new byte[0]);
    }

    /**
     * Parses the hostkey blob into a list of hostkeys
     *
     * @param hostkeyBlob the hostkey blob
     * @return
     */
    public static List<SshPublicKey<?, ?>> parseHostkeyBlob(byte[] hostkeyBlob) {
        int offset = 0;
        List<SshPublicKey<?, ?>> hostKeyList = new ArrayList<>();
        while (offset < hostkeyBlob.length) {
            BigInteger lengthKey =
                    new BigInteger(
                            Arrays.copyOfRange(
                                    hostkeyBlob,
                                    offset,
                                    offset = offset + DataFormatConstants.MPINT_SIZE_LENGTH));
            hostKeyList.add(
                    PublicKeyHelper.parse(
                            Arrays.copyOfRange(
                                    hostkeyBlob, offset, offset = offset + lengthKey.intValue())));
        }
        return hostKeyList;
    }
}
