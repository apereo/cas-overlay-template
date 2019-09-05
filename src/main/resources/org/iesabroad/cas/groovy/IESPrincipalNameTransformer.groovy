package org.iesabroad.cas

import org.apache.commons.lang.StringUtils

public class IESPrincipalNameTransformer {

    public String run(String formUserId, org.apache.logging.slf4j.Log4jLogger logger) {
        String sAMAccountName = formUserId;
        boolean isEmailAccount = StringUtils.contains(sAMAccountName, "@");

        if (isEmailAccount) {

            // Remove invalid characters
            String invalidChars = "\"/\\[]:;|=,+*?<>";
            if (StringUtils.containsAny(sAMAccountName, invalidChars)) {
                sAMAccountName = StringUtils.replaceChars(sAMAccountName, invalidChars, "");
            }

            // Valid but simplify
            String validChars = ".'-";
            if (StringUtils.containsAny(sAMAccountName, validChars)) {
                sAMAccountName = StringUtils.replaceChars(sAMAccountName, validChars, "");
            }

            // @ symbol is not allowed. Switch @ to _ for separation
            sAMAccountName = sAMAccountName.replace("@", "_");

            if (sAMAccountName.length() > 16) {
                sAMAccountName = sAMAccountName.substring(0, 16) + getAscii(formUserId);
            } else {
                sAMAccountName = sAMAccountName + getAscii(formUserId);
            }
        } else if (sAMAccountName.length() > 20) {
            sAMAccountName = sAMAccountName.substring(0, 20);
        }
        logger.info("attempting to login with converted username:" + sAMAccountName)
        return sAMAccountName;
    }

    /**
     * Generates a 4-digit number based on the total of each character's ASCII value. In addition,
     * the ASCII value is multiplied by a number based on its position on the string.
     */
    private static String getAscii(String input) {
        int total = 0;
        char[] characters = input.toCharArray();

        for (int i = 0; i < characters.length; i++) {
            int asciiValue = (int) characters[i];

            if (i % 3 == 0) {
                asciiValue *= 3;
            } else if (i % 2 == 0) {
                asciiValue *= 2;
            } else {
                asciiValue *= 1;
            }

            total += asciiValue;
        }

        return String.valueOf(total);
    }

}
