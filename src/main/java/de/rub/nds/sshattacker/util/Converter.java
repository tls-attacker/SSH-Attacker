package de.rub.nds.sshattacker.util;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.string.ModifiableString;
import de.rub.nds.sshattacker.constants.CharConstants;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class Converter {

    private static final Logger LOGGER = LogManager.getLogger();

    
    public static ModifiableString listOfAlgorithmsToModifiableString(List list){
        return ModifiableVariableFactory.safelySetValue(null, listofAlgorithmstoString(list));
    }
    
    public static String listofAlgorithmstoString(List list){
        StringBuilder builder = new StringBuilder();
        list.forEach(element -> builder.append(CharConstants.ALGORITHM_SEPARATOR).append(element));
        builder.deleteCharAt(0); // delete first separator before the first element
        return builder.toString();
    }
    
    public static List StringToAlgorithms(String string, Class myClass){
        String[] splitted = string.split(String.valueOf(CharConstants.ALGORITHM_SEPARATOR));
        // TODO make robust
        return Arrays.stream(splitted).map(s -> Enum.valueOf(myClass, string)).collect(Collectors.toList());
    }
}