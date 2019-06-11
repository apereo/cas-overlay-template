package org.iesabroad.cas;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.validator.routines.EmailValidator;
import org.apereo.cas.CipherExecutor;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.handler.PrincipalNameTransformer;
import org.apereo.cas.authentication.principal.PrincipalNameTransformerUtils;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.ldap.LdapAuthenticationProperties;
import org.apereo.cas.pm.BasePasswordManagementService;
import org.apereo.cas.pm.InvalidPasswordException;
import org.apereo.cas.pm.PasswordChangeBean;
import org.apereo.cas.util.CollectionUtils;
import org.apereo.cas.util.LdapUtils;
import org.iesabroad.cas.entity.UserVO;
import org.ldaptive.ConnectionFactory;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.Response;
import org.ldaptive.SearchFilter;
import org.ldaptive.SearchResult;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.DirContext;
import javax.naming.directory.ModificationItem;
import javax.naming.ldap.InitialLdapContext;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.sql.DataSource;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Date;
import java.util.GregorianCalendar;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

/**
 * This is {@link IesPasswordManagementService}.
 *
 * @author Mike Koehler, based on work by Misagh Moayyed
 * @since 5.0.0
 */
@Slf4j
@Transactional
public class IesPasswordManagementService extends BasePasswordManagementService {


    private static final String LDAP_IES_STUDENT = "IES-STUDENT";
    private static final String LDAP_IES_ALUMNI = "IES-ALUMNI";
    private static final String LDAP_IES_PROSPECT = "IES-PROSPECT";
    private static final String LDAP_STUDY_ABROAD_COORDINATOR = "IES-STUDY-ABROAD-COORDINATOR";
    private static final String LDAP_STUDY_ABROAD_ONLY = "IES-STUDY-ABROAD-ONLY";
    private static final String LDAP_INTERNSHIPS_COORDINATOR = "IES-INTERNSHIPS-COORDINATOR";
    private static final String LDAP_SYSTEM_ACCOUNT = "IES-SYSTEM-ACCOUNT";

    private static final String USER_SELECT_SQL = "SELECT * FROM CER_ACCOUNT with (NOLOCK) where lower(uid) = lower(?) or lower(sAMAccountName) = lower(?)";

    private static final String UPDATE_SQL_TEXT = "update CER_ACCOUNT set Ies_Password_Change_Date = ?, Ies_Password_Reset_Req = ? where Uid = ?";

    @Value("${cerberus.maxDaysForPasswordExpiration:45}")
    private int maxDaysForPasswordExpiration;

    @Value("${cerberus.maxDaysForStudentPasswordExpiration:730}")
    private int maxDaysForStudentPasswordExpiration ;

    @Value("${cerberus.maxDaysForSystemAccountPasswordExpiration:14600}")
    private int maxDaysForSystemAccountPasswordExpiration;

    @PersistenceContext
    private EntityManager entityManager;

    @Autowired
    private DataSource dataSource;

    private CasConfigurationProperties casProperties;

    private PrincipalNameTransformer principalNameTransformer = formUserId -> formUserId;

    public IesPasswordManagementService(final CipherExecutor<Serializable, String> cipherExecutor,
                                        CasConfigurationProperties casProperties) {
        super(casProperties.getAuthn().getPm(), cipherExecutor, casProperties.getServer().getPrefix());
        this.casProperties = casProperties;
        // We need to work around a probable bug in CAS - if you need to transform the userid to look them
        // up to login, you'll need to do the same to look them up to change their password. but the PM
        // properties don't have a way to indicate what transformation to use.  So we'll use the
        // transformation from cas.authn.ldap[0]
        if (casProperties.getAuthn().getLdap() != null) {
            LdapAuthenticationProperties ldap = casProperties.getAuthn().getLdap().get(0);
            if (ldap != null) {
                principalNameTransformer = PrincipalNameTransformerUtils.newPrincipalNameTransformer(
                        ldap.getPrincipalTransformation());
            } else {
                log.warn("Unable to find a PrincipalNameTransformation for password management");
            }
        } else {
            log.warn("Unable to find a PrincipalNameTransformation for password management");
        }
    }

    /**
     * Unlike the CAS LdapPasswordManagementService, we pull from the db
     *
     * @param username
     * @return
     */
    @Override
    public String findEmail(final String username) {
        if (entityManager != null) {
            log.debug("Transforming credential username via [{}]", this.principalNameTransformer.getClass().getName());

            UserVO user = entityManager.find(UserVO.class, username);
            if (user != null) {
                log.debug("Found db entry to use for the account email");

                String email;
                if (LDAP_IES_STUDENT.equalsIgnoreCase(user.getEmployeeType()) ||
                        LDAP_IES_PROSPECT.equalsIgnoreCase(user.getEmployeeType())) {
                    log.debug("Using Ies_School_Email [{}] to get email address for user");
                    email = user.getSchoolEmail();
                } else {
                    log.debug("Using Email [{}] to get email address for user");
                    email = user.getEmail();
                }
                log.debug("Found email address [{}] for user [{}]. Validating...", email, username);
                if (EmailValidator.getInstance().isValid(email)) {
                    log.debug("Email address [{}] matches a valid email address", email);
                    return email;
                }
                log.error("Email [{}] is not a valid address", email);
            } else {
                log.debug("Could not find user [{}]", username);

            }
        } else {
            log.debug("Could not connect to database, check logs for details");
        }
        return null;
    }

    @Override
    public boolean changeInternal(final Credential credential, final PasswordChangeBean bean) throws InvalidPasswordException {
        try {
            final UsernamePasswordCredential c = (UsernamePasswordCredential) credential;
            verifyPassword(c.getUsername(), bean.getPassword(), bean.getConfirmedPassword());
            final String transformedUsername = this.principalNameTransformer.transform(c.getUsername());
            log.trace("transformed credential username is {}", transformedUsername);

            for (LdapAuthenticationProperties ldap :casProperties.getAuthn().getLdap()) {
                final SearchFilter filter = LdapUtils.newLdaptiveSearchFilter(ldap.getSearchFilter(),
                        LdapUtils.LDAP_SEARCH_FILTER_DEFAULT_PARAM_NAME,
                        CollectionUtils.wrap(transformedUsername));
                log.debug("Constructed LDAP filter [{}] to update account password", filter);

                final ConnectionFactory factory = LdapUtils.newLdaptivePooledConnectionFactory(ldap);
                final Response<SearchResult> response = LdapUtils.executeSearchOperation(factory, ldap.getBaseDn(), filter);
                log.debug("LDAP response to account search for password change is [{}]", response);

                if (LdapUtils.containsResultEntry(response)) {
                    final String dn = response.getResult().getEntry().getDn();
                    log.debug("Updating account password for [{}]", dn);
                    if (save(ldap, dn, c.getPassword(), bean.getPassword(), c.getUsername())) {
                        log.debug("Successfully updated the account password for [{}]", dn);
                        return true;
                    }
                    log.error("Could not update the LDAP entry's password for [{}] and base DN [{}]", filter.format(), ldap.getBaseDn());
                    break;
                } else {
                    log.error("Could not locate an LDAP entry for [{}] using  [{}]", ldap.getBaseDn(), ldap.getName());
                }
            }
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
        }
        return false;
    }

    /**
     * Passwords: must contain 3 of the following 4 classes (uppercase, lowercase, numeric, non-alphanumeric)
     * must not contain the user's id
     * must be at least 8 characters long
     * @param userId
     * @param password
     * @param confirmedPassword
     */
    private void verifyPassword(String userId, String password, String confirmedPassword) {
        if (StringUtils.isEmpty(password) || StringUtils.isEmpty(confirmedPassword)) {
            throw new InvalidPasswordException("", "The New Password or Password Confirm field is empty. The password cannot be blank.", null);
        }
        if (!password.equals(confirmedPassword)) {
            throw new InvalidPasswordException("", "The New Password and Password Confirm fields do not match. Please try again.", null);
        }
        if ( StringUtils.containsIgnoreCase(password, userId) ) {
            throw new InvalidPasswordException("", "The New Password must comply with the password policy. Please try again.", null);
        }

        int count = 0;

        if (hasUppercase(password))
            count++;

        if (hasLowercase(password))
            count++;

        if (hasNumeric(password))
            count++;

        if (hasNonAlphanumeric(password))
            count++;

        if (password.length() < 8 || count < 3)
            throw new InvalidPasswordException();
    }

    private static boolean hasUppercase(String password) {
        return !password.equals(password.toLowerCase());
    }

    private static boolean hasLowercase(String password) {
        return !password.equals(password.toUpperCase());
    }

    private static boolean hasNumeric(String password) {
        return password.matches(".*\\d+.*");
    }

    private static boolean hasNonAlphanumeric(String password) {
        return !org.apache.commons.lang.StringUtils.isAlphanumeric(password);
    }

    @Override
    public Map<String, String> getSecurityQuestions(final String username) {
        final Map<String, String> set = new LinkedHashMap<>();
        try {
            for (LdapAuthenticationProperties ldap :casProperties.getAuthn().getLdap()) {
                final SearchFilter filter = LdapUtils.newLdaptiveSearchFilter(ldap.getSearchFilter(),
                        LdapUtils.LDAP_SEARCH_FILTER_DEFAULT_PARAM_NAME,
                        CollectionUtils.wrap(username));
                log.debug("Using LDAP {} LDAP filter [{}] to locate security questions", ldap.getName(), filter);

                final ConnectionFactory factory = LdapUtils.newLdaptivePooledConnectionFactory(ldap);
                final Response<SearchResult> response = LdapUtils.executeSearchOperation(factory, ldap.getBaseDn(), filter);
                log.debug("LDAP response for security questions [{}]", response);

                if (LdapUtils.containsResultEntry(response)) {
                    final LdapEntry entry = response.getResult().getEntry();
                    log.debug("Located LDAP entry [{}] in the response", entry);
                    final Map<String, String> qs = properties.getLdap().getSecurityQuestionsAttributes();
                    log.debug("Security question attributes are defined to be [{}]", qs);

                    qs.forEach((k, v) -> {
                        final LdapAttribute q = entry.getAttribute(k);
                        final LdapAttribute a = entry.getAttribute(v);
                        final String value = q.getStringValue();
                        final String answerValue = a.getStringValue();
                        if (q != null && a != null && StringUtils.isNotBlank(value) && StringUtils.isNotBlank(answerValue)) {
                            log.debug("Added security question [{}] with answer [{}]", value, answerValue);
                            set.put(value, answerValue);
                        }
                    });
                    break;
                } else {
                    log.debug("LDAP response did not contain a result for security questions");
                }
            }
        } catch (final Exception e) {
            log.error(e.getMessage(), e);
        }
        return set;
    }



    private InitialLdapContext getInitialContext(LdapAuthenticationProperties ldap) throws NamingException {
        Properties env = new Properties();
        env.setProperty(Context.SECURITY_PROTOCOL, (ldap.isUseSsl() ? "ssl" : ""));

        String factoryName = env.getProperty(Context.INITIAL_CONTEXT_FACTORY);
        if (factoryName == null) {
            factoryName = "com.sun.jndi.ldap.LdapCtxFactory";
            env.setProperty(Context.INITIAL_CONTEXT_FACTORY, factoryName);
        }

        env.setProperty(Context.SECURITY_AUTHENTICATION, "simple");

        env.setProperty(Context.PROVIDER_URL, ldap.getLdapUrl());
        env.setProperty(Context.SECURITY_PRINCIPAL, ldap.getBindDn());
        env.put(Context.SECURITY_CREDENTIALS, ldap.getBindCredential());

        // Added to avoid PartialResultException when searching base
        env.setProperty(Context.REFERRAL, ldap.isFailFast() ? "follow" : "ignore");
        log.debug("Logging into AD LDAP server");

        return new InitialLdapContext(env, null);
    }

    /**
     */
    @Transactional(propagation = Propagation.REQUIRED)
    boolean save(LdapAuthenticationProperties ldap, String dn, String oldPassword, String newPassword, String username) throws NamingException {
        try (Connection con = dataSource.getConnection();
             PreparedStatement ps = con.prepareStatement("update CERADM.CER_ACCOUNT\n" +
                     "set Ies_Password_Change_Date = ?\n" +
                     "\t, Ies_Password_Reset_Req = ?\n" +
                     "where Uid = ?")) {
            con.setAutoCommit(false);

            InitialLdapContext ctx = getInitialContext(ldap);
            UserVO user = entityManager.find(UserVO.class, username);
            ps.setDate(1, determineExpirationDate(user.getEmployeeType()));
            ps.setString(2,"N");

            String quotedPassword = "\"" + newPassword + "\"";
            char unicodePwd[] = quotedPassword.toCharArray();
            byte pwdArray[] = new byte[unicodePwd.length * 2];
            for (int i = 0; i < unicodePwd.length; i++) {
                pwdArray[i * 2 + 1] = (byte) (unicodePwd[i] >>> 8);
                pwdArray[i * 2 + 0] = (byte) (unicodePwd[i] & 0xff);
            }

            ModificationItem[] modItems = new ModificationItem[1];
            modItems[0] = new ModificationItem(DirContext.REPLACE_ATTRIBUTE, new BasicAttribute("UnicodePwd", pwdArray));
            ctx.modifyAttributes(dn, modItems);

            con.commit();
            return true;
        } catch (Exception e ) {
            log.error(e.getMessage(), e);
            return false;
        }
    }

    private Date determineExpirationDate(String employeeType) {
        return determineExpirationDate(determineDaysToExpiration(employeeType));
    }

    private Date determineExpirationDate(int nbrDaysForPasswordExpiration) {
        GregorianCalendar gc = new GregorianCalendar();
        gc.add(GregorianCalendar.DAY_OF_YEAR, nbrDaysForPasswordExpiration);
        return new Date(gc.getTimeInMillis());
    }

    /**
     * Returns whichever of our three password-expiration-in-days values applies to the passed employee type.
     *
     * @param employeeType
     * @return
     */
    private int determineDaysToExpiration(String employeeType) {
        int passwordExpiration;

        if (LDAP_IES_STUDENT.equalsIgnoreCase(employeeType) || LDAP_IES_ALUMNI.equalsIgnoreCase(employeeType)
                || LDAP_IES_PROSPECT.equalsIgnoreCase(employeeType)
                || LDAP_STUDY_ABROAD_COORDINATOR.equalsIgnoreCase(employeeType)
                || LDAP_STUDY_ABROAD_ONLY.equalsIgnoreCase(employeeType)
                || LDAP_INTERNSHIPS_COORDINATOR.equalsIgnoreCase(employeeType)) {
            /*
             * Note: Study Abroad Coordinators get the same expiration rule as students.
             */
            passwordExpiration = maxDaysForStudentPasswordExpiration;
        } else if (LDAP_SYSTEM_ACCOUNT.equalsIgnoreCase(employeeType)) {
            passwordExpiration = maxDaysForSystemAccountPasswordExpiration;
        } else
            passwordExpiration = maxDaysForPasswordExpiration;

        return passwordExpiration;
    }


}
