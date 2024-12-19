/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.common;

import de.rub.nds.modifiablevariable.ModifiableVariable;
import de.rub.nds.modifiablevariable.util.ReflectionHelper;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ModifiableVariableHolder implements Serializable {

    private static final Logger LOGGER = LogManager.getLogger();

    protected ModifiableVariableHolder() {
        super();
    }

    protected ModifiableVariableHolder(ModifiableVariableHolder other) {
        super();
    }

    /**
     * Copies this ModifiableVariableHolder
     *
     * @return A copy of this ModifiableVariableHolder
     */
    public abstract ModifiableVariableHolder createCopy();

    /**
     * Lists all the modifiable variables declared in the class
     *
     * @return List of all modifiableVariables declared in this class
     */
    public List<Field> getAllModifiableVariableFields() {
        return ReflectionHelper.getFieldsUpTo(getClass(), null, ModifiableVariable.class);
    }

    /**
     * Returns a random field representing a modifiable variable from this class
     *
     * @param random The RandomNumber generator that should be used
     * @return A random ModifiableVariableField
     */
    public Field getRandomModifiableVariableField(Random random) {
        List<Field> fields = getAllModifiableVariableFields();
        int randomField = random.nextInt(fields.size());
        return fields.get(randomField);
    }

    /**
     * Returns a list of all the modifiable variable holders in the object, including this instance
     *
     * @return All ModifiableVariableHolders
     */
    public List<ModifiableVariableHolder> getAllModifiableVariableHolders() {
        List<ModifiableVariableHolder> holders = new LinkedList<>();
        holders.add(this);
        return holders;
    }

    /**
     * Returns a random modifiable variable holder
     *
     * @param random The RandomNumberGenerator that should be used
     * @return A Random ModifiableVariableHolder
     */
    public ModifiableVariableHolder getRandomModifiableVariableHolder(Random random) {
        List<ModifiableVariableHolder> holders = getAllModifiableVariableHolders();
        int randomHolder = random.nextInt(holders.size());
        return holders.get(randomHolder);
    }

    public void resetUsingRefelctions() {
        List<Field> fields = getAllModifiableVariableFields();
        for (Field field : fields) {
            field.setAccessible(true);

            ModifiableVariable<?> mv = null;
            try {
                mv = (ModifiableVariable<?>) field.get(this);
            } catch (IllegalArgumentException | IllegalAccessException ex) {
                LOGGER.warn("Could not retrieve ModifiableVariables");
                LOGGER.debug(ex);
            }
            if (mv != null) {
                if (mv.getModification() != null || mv.isCreateRandomModification()) {
                    mv.setOriginalValue(null);
                } else {
                    try {
                        field.set(this, null);
                    } catch (IllegalArgumentException | IllegalAccessException ex) {
                        LOGGER.warn("Could not strip ModifiableVariable without Modification");
                    }
                }
            }
        }
    }
}
