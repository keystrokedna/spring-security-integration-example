package com.keystrokedna.examples.spring;

import lombok.extern.slf4j.Slf4j;
import org.apache.tomcat.util.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Optional;

import static org.springframework.web.util.UriComponentsBuilder.fromHttpUrl;

@Slf4j
@Component
public class KsdnaTemplate {

    private final KeystrokeDNASettings settings;

    private final RestTemplate restTemplate;

    private String token;

    private Long expired = 0L;

    @Autowired
    public KsdnaTemplate(KeystrokeDNASettings settings, @Qualifier("ksdnaRestTemplate") RestTemplate restTemplate) {
        this.settings = settings;
        this.restTemplate = restTemplate;
    }

    public String getToken() {
        return getTokenSafe().orElseThrow(() -> new RuntimeException("Cannot get token"));
    }

    public Optional<String> getTokenSafe() {
        long now = Instant.now().getEpochSecond();
        if (token == null || now > expired) {
            String url = settings.getUrl() + "/oauth/token";
            String auth = settings.getKey() + ":" + settings.getSecret();
            byte[] encodedAuth = Base64.encodeBase64(
                    auth.getBytes(StandardCharsets.US_ASCII));
            String authHeader = "Basic " + new String(encodedAuth);
            HttpHeaders headers = new HttpHeaders();
            headers.add(HttpHeaders.AUTHORIZATION, authHeader);
            TokenResponse body;
            try {
                body = restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(headers), TokenResponse.class).getBody();
            } catch (HttpClientErrorException.BadRequest e) {
                log.error("Token bad request [{}]", e.getResponseBodyAsString());
                throw e;
            }
            token = Optional.ofNullable(body).map(TokenResponse::getAccessToken)
                    .orElse(null);
            expired = now + Optional.ofNullable(body).map(TokenResponse::getExpiresIn)
                    .orElse(0L);
        }
        return Optional.ofNullable(token);
    }

    public ScoreResponse getScore(HttpServletRequest request) {
        String remoteAddr = Optional.ofNullable(request.getRemoteAddr())
                .orElse("127.0.0.1");
        String signature = Optional.ofNullable(request.getParameter("signature"))
                .orElse("");
        String value = Optional.ofNullable(request.getParameter("username"))
                .orElse("");
        String userAgent = Optional.ofNullable(request.getHeader(HttpHeaders.USER_AGENT))
                .orElse("");
        Assert.hasText(signature, "Empty signature");
        Assert.hasText(userAgent, "Empty user agent");
        Assert.hasText(value, "Empty username");
        String url = settings.getUrl() + "/trusted/identify";
        UriComponentsBuilder builder = fromHttpUrl(url);
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + getToken());
        headers.add("X-Forwarded-For", remoteAddr);
        headers.add(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        builder.queryParam("username", value);
        builder.queryParam("value", value);
        builder.queryParam("user_agent", userAgent);
        builder.queryParam("signature", signature);
        try {
            return Optional.ofNullable(restTemplate.exchange(builder.toUriString(), HttpMethod.POST, new HttpEntity<>(headers), ScoreResponse.class).getBody())
                    .orElseThrow(() -> new RuntimeException("Cannot get a score"));
        } catch (HttpClientErrorException.BadRequest e) {
            log.error("Score bad request [{}]", e.getResponseBodyAsString());
            throw e;
        }
    }

    /**
     * Approve a device by a code
     *
     * @param code  String code
     * @param value Value 0 or 1
     * @return result of execution
     */
    public boolean approveDeviceByCode(String code, String value) {
        boolean val = "1".equalsIgnoreCase(value) || "true".equalsIgnoreCase(value);
        HttpMethod method = val ? HttpMethod.POST : HttpMethod.DELETE;
        String url = settings.getUrl() + "/devices/approve/" + code;
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + getToken());
        try {
            restTemplate.exchange(url, method, new HttpEntity<>(headers), ScoreResponse.class).getBody();
            log.info("Device approve set to [{}] by code [{}]", val, code);
            return true;
        } catch (HttpClientErrorException.BadRequest e) {
            log.error("Approve device by code bad request [{}]", e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Cannot set device approve by code [{}]", e.getLocalizedMessage());
        }
        return false;
    }

    /**
     * Approve a device by a hash
     *
     * @param deviceHash String device hash
     */
    public void approveDeviceByHash(String deviceHash) {
        String url = settings.getUrl() + "/devices/approve/hash/" + deviceHash;
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + getToken());
        try {
            restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(headers), ScoreResponse.class).getBody();
            log.info("Device approved by hash [{}]", deviceHash);
        } catch (HttpClientErrorException.BadRequest e) {
            log.error("Approve device by hash bad request [{}]", e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Cannot approve device by hash [{}]", e.getLocalizedMessage());
        }
    }

    /**
     * Approve a signature by an ID
     *
     * @param signatureId Signature id from Keystroke DNA API response
     */
    public void approveSignature(String signatureId) {
        String url = settings.getUrl() + "/signatures/approve/" + signatureId;
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + getToken());
        try {
            restTemplate.exchange(url, HttpMethod.POST, new HttpEntity<>(headers), ScoreResponse.class).getBody();
            log.info("Signature [{}] approved", signatureId);
        } catch (HttpClientErrorException.BadRequest e) {
            log.error("Approve signature bad request [{}]", e.getResponseBodyAsString());
        } catch (Exception e) {
            log.error("Cannot approve signature [{}]", e.getLocalizedMessage());
        }
    }
}
