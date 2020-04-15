package com.keystrokedna.examples.spring;

import lombok.extern.slf4j.Slf4j;
import org.jboss.aerogear.security.otp.Totp;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.util.stream.Collectors.toList;
import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@Slf4j
@Component
public class KeystrokeDNAService implements AuthenticationSuccessHandler {

    private static final String ROLES_KEY = "KSDNA_ROLES_BACKUP";

    private static final String ROLES_DELIMITER = ";";

    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    private final KsdnaTemplate ksdnaTemplate;

    private final KeystrokeDNASettings settings;

    @Autowired
    public KeystrokeDNAService(KsdnaTemplate ksdnaTemplate, KeystrokeDNASettings settings) {
        this.ksdnaTemplate = ksdnaTemplate;
        this.settings = settings;
    }

    /**
     * Set Security Context authentication to null and forward to login with error
     *
     * @param request  HttpServletRequest
     * @param response HttpServletResponse
     * @throws IOException when redirecting
     */
    private void failed(HttpServletRequest request, HttpServletResponse response) throws IOException {
        SecurityContextHolder.getContext().setAuthentication(null);
        request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException("Keystroke DNA score is too low"));
        redirectStrategy.sendRedirect(request, response, "/login?error=true");
    }

    /**
     * Send user to a success page
     *
     * @param request  HttpServletRequest
     * @param response HttpServletResponse
     * @throws IOException when redirecting
     */
    private void success(HttpServletRequest request, HttpServletResponse response) throws IOException {
        redirectStrategy.sendRedirect(request, response, "/success/");
    }

    /**
     * Set new specific roles into Security Context
     *
     * @param session HttpSession
     * @param roles   Set<String> set of roles
     * @param backup  Backup previous roles or not
     */
    private void setRoles(HttpSession session, Set<String> roles, boolean backup) {
        SecurityContext sc = SecurityContextHolder.getContext();
        Authentication auth = sc.getAuthentication();
        if (backup) {
            String rolesBkp = auth.getAuthorities()
                    .stream()
                    .map(Object::toString)
                    .collect(Collectors.joining(ROLES_DELIMITER));
            session.setAttribute(ROLES_KEY, rolesBkp);
        }
        List<GrantedAuthority> updatedAuthorities = roles.stream()
                .map(s -> s.startsWith("ROLE_") ? s.trim() : "ROLE_" + s.trim())
                .map(SimpleGrantedAuthority::new)
                .collect(toList());
        UsernamePasswordAuthenticationToken newAuth = new UsernamePasswordAuthenticationToken(auth.getPrincipal(), auth.getCredentials(), updatedAuthorities);
        newAuth.setDetails(auth.getDetails());
        sc.setAuthentication(newAuth);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);
    }

    /**
     * Set on role with backup of previous roles
     *
     * @param session HttpSession
     * @param role    Specific role
     */
    private void setRole(HttpSession session, String role) {
        setRoles(session, Collections.singleton(role), true);
    }

    /**
     * Restore previous roles from the session
     *
     * @param session HttpSession
     */
    private void restoreRoles(HttpSession session) {
        Optional.ofNullable(session.getAttribute(ROLES_KEY))
                .ifPresent(o -> {
                    Set<String> bkpRoles = Stream.of(o.toString().split(ROLES_DELIMITER))
                            .collect(Collectors.toSet());
                    setRoles(session, bkpRoles, false);
                });
    }


    /**
     * Check if the submitted code is valid
     *
     * @param code User submitted code
     * @return true or false
     */
    private boolean isValidLong(String code) {
        try {
            Long.parseLong(code);
        } catch (NumberFormatException e) {
            return false;
        }
        return true;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        ScoreResponse score = ksdnaTemplate.getScore(request);
        log.warn("KeystrokeDNA score [{}]", score);

        HttpSession httpSession = request.getSession(true);
        if (score.getStatus() == 0) { // brand new biometric profile
            success(request, response);
        } else if (score.getStatus() == 3) { // normal scoring
            request.getSession(true);
            if (score.isFailed()) {
                failed(request, response);
            } else if (!score.isFailed() && !score.isSuccess()) { // suspicious, maybe it's False Negative
                if (settings.isUse2fa()) {
                    httpSession.setAttribute("ksdna_signature_id", score.getSignatureId());
                    setRole(httpSession, "2FA");
                    redirectStrategy.sendRedirect(request, response, "/2fa/"); // let's confirm via 2FA
                } else {
                    failed(request, response);
                }
            } else if (CollectionUtils.isEmpty(score.getNotApproved())) {
                success(request, response);
            } else {
                httpSession.setAttribute("not_approved_devices", score.getNotApproved());
                setRole(httpSession, "APPROVE_DEVICE");
                redirectStrategy.sendRedirect(request, response, "/approve_device/");
            }
        } else if (score.getStatus() == 2) { // new device
            if (!settings.isUse2fa()) {
                setRole(httpSession, "NEW_DEVICE");
                redirectStrategy.sendRedirect(request, response, "/new_device/");
            } else {
                setRole(httpSession, "2FA");
                httpSession.setAttribute("ksdna_device_hash", score.getDeviceHash());
                redirectStrategy.sendRedirect(request, response, "/2fa/"); // let's confirm via 2FA
            }
        }
    }

    /**
     * Approve a device or a particular signature with TOTP
     *
     * @param code           User submitted TOTP
     * @param authentication Authentication
     * @param request        HttpServletRequest
     * @param response       HttpServletResponse
     * @throws IOException when redirecting
     */
    public void approve(String code, Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws IOException {
        String cleanCode = code.replaceAll("\\s", "");
        Totp totp = new Totp(TOTPUtils.secretFromUsername(((User) authentication.getPrincipal()).getUsername()));
        if (!isValidLong(cleanCode) || !totp.verify(cleanCode)) {
            throw new BadCredentialsException("Invalid verification code");
        }
        HttpSession session = request.getSession(false);
        if (session == null) {
            throw new IllegalStateException("No session");
        }
        Optional.ofNullable(session.getAttribute("ksdna_signature_id"))
                .map(Object::toString)
                .ifPresent(ksdnaTemplate::approveSignature);
        Optional.ofNullable(session.getAttribute("ksdna_device_hash"))
                .map(Object::toString)
                .ifPresent(ksdnaTemplate::approveDeviceByHash);
        restoreRoles(session);
        success(request, response);
    }

    /**
     * Approve a bunch or single devices by codes from Keystroke DNA server response
     *
     * @param codes    Map of code/value
     * @param request  HttpServletRequest
     * @param response HttpServletResponse
     * @throws IOException when redirecting
     */
    public void approveDevicesByCodes(Map<String, String> codes, HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, Boolean> results = codes.entrySet()
                .parallelStream()
                .map(e -> new Tuple<>(e.getKey(), ksdnaTemplate.approveDeviceByCode(e.getKey(), e.getValue())))
                .collect(Collectors.toMap(Tuple::getKey, Tuple::getValue));
        for (Map.Entry<String, Boolean> entry : results.entrySet()) {
            log.info("Code [{}] processed [{}]", entry.getKey(), entry.getValue());
        }
        restoreRoles(request.getSession(true));
        success(request, response);
    }

}