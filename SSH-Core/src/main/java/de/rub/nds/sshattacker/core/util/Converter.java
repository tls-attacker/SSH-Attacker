/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.sshattacker.core.constants.CharConstants;
import de.rub.nds.sshattacker.core.constants.DataFormatConstants;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class Converter {

    public static <T extends Enum<T>> ModifiableString listOfAlgorithmsToModifiableString(
            List<T> list) {
        return ModifiableVariableFactory.safelySetValue(null, listOfAlgorithmsToString(list));
    }

    public static String joinStringList(List<String> list, char seperator) {
        if (list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        for (String listElement : list) {
            builder.append(seperator).append(listElement);
        }
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }

    public static <T extends Enum<T>> String listOfAlgorithmsToString(List<T> list) {
        if (list.isEmpty()) {
            return "";
        }

        StringBuilder builder = new StringBuilder();
        list.forEach(
                element ->
                        builder.append(CharConstants.ALGORITHM_SEPARATOR)
                                .append(element.toString()));
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }

    public static <T extends Enum<T>> List<T> nameListToEnumValues(
            String string, Class<T> enumClass) {
        return Arrays.stream(string.split(String.valueOf(CharConstants.ALGORITHM_SEPARATOR)))
                .map(
                        algorithmName ->
                                Arrays.stream(enumClass.getEnumConstants())
                                        .filter(
                                                enumValue ->
                                                        enumValue.toString().equals(algorithmName))
                                        .findFirst()
                                        .orElse(null))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public static byte[] bigIntegerToMpint(BigInteger input) {
        byte[] value = input.toByteArray();
        byte[] length =
                ArrayConverter.intToBytes(value.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        return ArrayConverter.concatenate(length, value);
    }

    public static byte[] byteArrayToMpint(byte[] input) {
        byte[] mpint = input;
        if ((input[0] & 0x80) == 0x80) { // need to append 0 if MSB would be set
            // (twos complement)
            mpint = ArrayConverter.concatenate(new byte[] {0}, input);
        }
        byte[] length =
                ArrayConverter.intToBytes(mpint.length, DataFormatConstants.MPINT_SIZE_LENGTH);
        mpint = ArrayConverter.concatenate(length, mpint);
        return mpint;
    }

    public static byte[] stringToLengthPrefixedBinaryString(String input) {
        return bytesToLengthPrefixedBinaryString(input.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] bytesToLengthPrefixedBinaryString(byte[] input) {
        return ArrayConverter.concatenate(
                ArrayConverter.intToBytes(input.length, DataFormatConstants.STRING_SIZE_LENGTH),
                input);
    }

    public static byte booleanToByte(boolean value) {
        return (byte) (value ? 0x01 : 0x00);
    }

    public static boolean byteToBoolean(byte value) {
        return value != (byte) 0x00;
    }

    // TODO: Replace by ArrayConverter.bytesToLong() as soon as fixed
    public static long byteArrayToLong(byte[] value) {
        long result = 0;
        for (int i = 0; i < Long.BYTES && i < value.length; i++) {
            result <<= Byte.SIZE;
            result |= (value[i] & 0xFF);
        }
        return result;
    }

    public static int byteArrayToInt(byte[] value) {
        return new BigInteger(value).intValue();
    }

    public static byte[] intToByteArray(int value) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(DataFormatConstants.UINT32_SIZE);
        byteBuffer.putInt(value);
        return byteBuffer.array();
    }

    public static String byteArrayToString(byte[] value) {
        return new String(value, StandardCharsets.US_ASCII);
    }

    public static ModifiableString byteArrayToModifiableString(byte[] value) {
        String s = byteArrayToString(value);
        ModifiableString ms = new ModifiableString();
        ms.setOriginalValue(s);
        return ms;
    }

    public static ModifiableString stringToModifiableString(String s) {
        ModifiableString ms = new ModifiableString();
        ms.setOriginalValue(s);
        return ms;
    }

}
