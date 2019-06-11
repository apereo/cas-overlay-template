package org.iesabroad.cas;

import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.util.spring.ApplicationContextProvider;
import org.iesabroad.cas.entity.UserVO;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.AuthenticationResponseHandler;
import org.ldaptive.auth.ext.ActiveDirectoryAccountState;
import org.ldaptive.auth.ext.ActiveDirectoryAccountState.Error;
import org.springframework.context.ApplicationContext;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import java.time.Instant;
import java.time.Period;
import java.time.ZoneId;
import java.time.ZonedDateTime;

@Slf4j
public class IesAuthenticationResponseHandler implements AuthenticationResponseHandler {


    @PersistenceContext
    private EntityManager entityManager;

    private Period warningPeriod = Period.of(0, 0, 7);

    public IesAuthenticationResponseHandler(Period warning) {
        this.setWarningPeriod(warning);
    }

    public IesAuthenticationResponseHandler() {
    }

    private void init() {
        if (entityManager == null) {
            // we're instanitiated by reflection, si we need to populate entitymanager since spring
            // doesn't get a chance to.
            ApplicationContext applicationContext = ApplicationContextProvider.getApplicationContext();
            applicationContext.getAutowireCapableBeanFactory().autowireBean(this);
        }
    }

    public void handle(AuthenticationResponse response) {
        init();
        if (response.getResult()) {
            LdapEntry entry = response.getLdapEntry();
            LdapAttribute userName = entry.getAttribute("sAMAccountName");
            if (userName != null) {

                // use cerbadm rather than ldap expirations
                String userId = userName.getStringValue();
                if (userId != null) {
                    UserVO user = entityManager.find(UserVO.class, userId);

                    Instant exp = null;
                    if (user.getPasswordChangeDate() != null) {
                        exp = (user.getPasswordChangeDate().toInstant());
                    }

                    if (exp != null) {
                        if (Instant.now().isAfter(exp)) {
                            response.setAccountState(new ActiveDirectoryAccountState(Error.PASSWORD_EXPIRED));
                        } else if (!user.getUserEnabled()) {
                            response.setAccountState(new ActiveDirectoryAccountState(Error.ACCOUNT_DISABLED));
                        } else if (this.warningPeriod != null) {
                            Instant warn = exp.minus(this.warningPeriod);
                            if (Instant.now().isAfter(warn)) {
                                response.setAccountState(new ActiveDirectoryAccountState(ZonedDateTime.ofInstant(exp, ZoneId.systemDefault())));
                            }
                        } else {
                            response.setAccountState(new ActiveDirectoryAccountState(ZonedDateTime.ofInstant(exp, ZoneId.systemDefault())));
                        }
                    }
                } else {
                    log.warn("No username attribute for user, should not happen");
                    response.setAccountState(new ActiveDirectoryAccountState(Error.NO_SUCH_USER));
                }
            } else {
                log.warn("No entry for user, should not happen");
                response.setAccountState(new ActiveDirectoryAccountState(Error.NO_SUCH_USER));
            }
        } else if (response.getMessage() != null) {
            Error adError = Error.parse(response.getMessage());
            if (adError != null) {
                response.setAccountState(new ActiveDirectoryAccountState(adError));
            }
        }

    }

    public Period getWarningPeriod() {
        return this.warningPeriod;
    }

    public void setWarningPeriod(Period period) {
        this.warningPeriod = period;
    }

    public String toString() {
        return String.format("[%s@%d:: warningPeriod=%s]", this.getClass().getName(), this.hashCode(), this.warningPeriod);
    }
}
