/**
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2021 Ruhr University Bochum, Paderborn University,
 * and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import java.nio.charset.StandardCharsets;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Converter {

    private static final Logger LOGGER = LogManager.getLogger();

    public static <T extends Enum<T>> ModifiableString listOfAlgorithmsToModifiableString(List<T> list) {
        return ModifiableVariableFactory.safelySetValue(null, listOfAlgorithmsToString(list));
    }

    public static <T extends Enum<T>> String listOfAlgorithmsToString(List<T> list) {
        if(list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        list.forEach(element -> builder.append(CharConstants.ALGORITHM_SEPARATOR).append(element.toString()));
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }

    public static <T extends Enum<T>> List<T> stringToAlgorithms(String string, Class<T> algoClass) {
        String[] splitted = string.split(String.valueOf(CharConstants.ALGORITHM_SEPARATOR));
        List<T> list = new LinkedList<>();
        for (String rawAlgo : splitted) {
            T algo = Enum.valueOf(algoClass, toEnumName(rawAlgo).toUpperCase());
            list.add(algo);
        }
        return list;
    }

    private static String toEnumName(String input) {
        // TODO: This method will fail to parse named elliptic curve algorithms
        String result = input.replace('-', '_').replace('.', '_').replace('@', '_').replace("3des", "TRIPLE_DES");
        if (result.equals("")) {
            return "none";
        }
        return result;
    }

    public static byte[] byteArrayToMpint(byte[] input) {
        byte[] mpint = input;
        if ((input[0] & 0x80) == 0x80) { // need to append 0 if MSB would be set
                                         // (twos complement)
            mpint = ArrayConverter.concatenate(new byte[] { 0 }, input);
        }
        byte[] length = ArrayConverter.intToBytes(mpint.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        mpint = ArrayConverter.concatenate(length, mpint);
        return mpint;
    }

    public static byte[] stringToLengthPrefixedBinaryString(String input) {
        return bytesToLengthPrefixedBinaryString(input.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] bytesToLengthPrefixedBinaryString(byte[] input) {
        return ArrayConverter.concatenate(
                ArrayConverter.intToBytes(input.length, DataFormatConstants.STRING_SIZE_LENGTH), input);
    }

    public static byte[] bytesToBytesWithSignByte(byte[] input) {
        if ((input[0] & 0x80) >> 7 == 1) {
            return ArrayConverter.concatenate(new byte[] { 0x00 }, input);
        }
        return input;
    }
}
