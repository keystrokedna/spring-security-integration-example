package com.keystrokedna.examples.spring;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotEmpty;
import java.util.List;

@Data
@Validated
@Configuration
@ConfigurationProperties(prefix = "security")
public class UsersSettings {

    @NotEmpty(message = "Example users list cannot be empty")
    private List<User> users;

    @Data
    public static class User {

        private String name;

        private String pass;
    }
}
