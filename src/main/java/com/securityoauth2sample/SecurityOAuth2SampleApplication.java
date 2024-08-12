package com.securityoauth2sample;

import com.securityoauth2sample.config.AppConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@EnableConfigurationProperties(AppConfig.class)
@SpringBootApplication
public class SecurityOAuth2SampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityOAuth2SampleApplication.class, args);
    }

}
