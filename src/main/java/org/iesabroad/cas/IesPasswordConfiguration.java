package org.iesabroad.cas;

import lombok.extern.slf4j.Slf4j;
import org.apereo.cas.CipherExecutor;
import org.apereo.cas.config.LdapAuthenticationConfiguration;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.pm.PasswordManagementService;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.autoconfigure.jdbc.DataSourceBuilder;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.annotation.EnableTransactionManagement;

import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;
import java.util.Properties;


@Configuration("IesPasswordConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@EntityScan(basePackages = {"org.iesabroad.cas.entity"})
@Slf4j
@EnableTransactionManagement
public class IesPasswordConfiguration extends LdapAuthenticationConfiguration {

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;


    @Autowired
    private Environment environment;

    @Autowired
    private CasConfigurationProperties casProperties;

    @Autowired
    @Qualifier("passwordManagementCipherExecutor")
    private CipherExecutor passwordManagementCipherExecutor;

    @Bean
    @RefreshScope
    public PasswordManagementService passwordChangeService() {
        return new IesPasswordManagementService(passwordManagementCipherExecutor,
                casProperties);
    }

    @Bean
    public DataSource dataSource() {
        log.debug("Creating datasource using: " + System.lineSeparator()
            + "datasource.username" + environment.getProperty("spring.datasource.username") + System.lineSeparator()
            + "datasource.url" + environment.getProperty("spring.datasource.url") + System.lineSeparator()
            + "datasource.driver" + environment.getProperty("spring.datasource.driver") + System.lineSeparator()
            + "datasource.username" + environment.getProperty("spring.datasource.username") + System.lineSeparator());
        return DataSourceBuilder
                .create()
                .username(environment.getProperty("spring.datasource.username"))
                .password(environment.getProperty("spring.datasource.password"))
                .url(environment.getProperty("spring.datasource.url"))
                .driverClassName(environment.getProperty("spring.datasource.driver"))
                .build();
    }

    @Bean
    public EntityManagerFactory entityManagerFactory()  {
        log.debug("Creating datasource using: " + System.lineSeparator()
                + "datasource.username" + environment.getProperty("spring.datasource.username") + System.lineSeparator()
                + "datasource.url" + environment.getProperty("spring.datasource.url") + System.lineSeparator()
                + "datasource.driver" + environment.getProperty("spring.datasource.driver") + System.lineSeparator()
                + "datasource.username" + environment.getProperty("spring.datasource.username") + System.lineSeparator());
        try {
            Class.forName(environment.getProperty("spring.datasource.url"));
        } catch (ClassNotFoundException e) {
            log.error(e.getMessage(), e);
        }
        LocalContainerEntityManagerFactoryBean em
                = new LocalContainerEntityManagerFactoryBean();
        em.setDataSource(dataSource());

        em.setPackagesToScan(new String[]{"org.iesabroad.cas.entity"});

//        JpaVendorAdapter vendorAdapter = ;
        em.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        Properties properties = new Properties();
        properties.setProperty("hibernate.hbm2ddl.auto", "create-drop");
        properties.setProperty(
                "hibernate.dialect", environment.getProperty("spring.jpa.database-platform"));

        em.afterPropertiesSet();
        return em.getNativeEntityManagerFactory();
    }
}
