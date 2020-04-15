package com.keystrokedna.examples.spring;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.validation.annotation.Validated;

import javax.validation.constraints.NotBlank;

@Data
@Validated
@Configuration
@ConfigurationProperties(prefix = "ksdna")
public class KeystrokeDNASettings {

    @NotBlank(message = "Keystroke DNA application ID cannot be blank")
    private String key;

    @NotBlank(message = "Keystroke DNA application secret cannot be blank")
    private String secret;

    @NotBlank(message = "Keystroke DNA API base URL cannot be empty")
    private String url = "https://api.keystrokedna.com";

    private boolean use2fa = true;

}
