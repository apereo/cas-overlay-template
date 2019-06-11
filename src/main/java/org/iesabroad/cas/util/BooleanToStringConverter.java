package org.iesabroad.cas.util;

import javax.persistence.AttributeConverter;

public class BooleanToStringConverter implements AttributeConverter<Boolean, String> {

    @Override
    public String convertToDatabaseColumn(Boolean attribute) {
        if (attribute == null) {
            return null;
        }
        if (attribute) {
            return "Y";
        }
        return "N";
    }

    @Override
    public Boolean convertToEntityAttribute(String dbData) {
        if (dbData == null) {
            return null;
        }
        if (dbData.equalsIgnoreCase("Y")) {
            return Boolean.TRUE;
        }
        return Boolean.FALSE;
    }
}
