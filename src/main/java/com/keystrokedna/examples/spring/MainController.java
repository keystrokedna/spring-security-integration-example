/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.keystrokedna.examples.spring;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotBlank;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Controller
public class MainController {

    private final KeystrokeDNASettings ksdnaSettings;

    private final KeystrokeDNAService keystrokeDNAService;

    @Autowired
    public MainController(KeystrokeDNASettings ksdnaSettings, KeystrokeDNAService keystrokeDNAService) {
        this.ksdnaSettings = ksdnaSettings;
        this.keystrokeDNAService = keystrokeDNAService;
    }

    @RequestMapping("/")
    public String root() {
        return "redirect:/login";
    }

    @RequestMapping("/success")
    public String success() {
        return "success";
    }

    @RequestMapping("/new_device")
    public String newDevice() {
        return "new_device";
    }

    @RequestMapping("/login")
    public String login(Model model, HttpServletRequest request) {
        model.addAttribute("ksdna", ksdnaSettings);
        model.addAttribute("loginError", Optional.ofNullable(request.getParameter("error")).orElse(null));
        return "login";
    }

    @RequestMapping("/logout")
    public String logout() {
        return "logout";
    }

    @GetMapping("/2fa")
    public String show2fa() {
        return "2fa";
    }

    @RequestMapping("/2fa_invalid_code")
    public String invalidCode() {
        return "invalid_code";
    }

    @PostMapping("/approve_device")
    public String approveDevice(final HttpServletRequest request, HttpServletResponse response) throws IOException {
        Map<String, String> codes = Collections.list(request.getParameterNames())
                .parallelStream()
                .filter(s -> s.startsWith("keys_"))
                .map(s -> {
                    String code = s.substring(5);
                    String value = request.getParameter(s);
                    return new Tuple<>(code, value);
                })
                .collect(Collectors.toMap(Tuple::getKey, Tuple::getValue));
        keystrokeDNAService.approveDevicesByCodes(codes, request, response);
        return null;
    }

    @GetMapping("/approve_device")
    public String approveDeviceView(Model model, HttpSession session) {
        model.addAttribute("forApproving", session.getAttribute("not_approved_devices"));
        return "approve_device";
    }

    @PostMapping("/2fa_code")
    public String submit2FACode(@NotBlank @RequestParam("code") String code,
                                Authentication authentication, HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            keystrokeDNAService.approve(code, authentication, request, response);
        } catch (BadCredentialsException e) {
            return "redirect:/2fa_invalid_code/";
        }
        return null;
    }

    @RequestMapping("/2fa_qr_code")
    public String qrCode(Authentication authentication, Model model) throws UnsupportedEncodingException {
        model.addAttribute("qr_code_link", TOTPUtils.generateQRUrl((User) authentication.getPrincipal()));
        return "qr_code";
    }

    @RequestMapping("/invalid_session")
    public String invalidSession() {
        return "invalid_session";
    }

}
