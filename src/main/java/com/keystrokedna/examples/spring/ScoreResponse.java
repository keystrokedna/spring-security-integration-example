package com.keystrokedna.examples.spring;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
class ScoreResponse {

    private Float completeness;

    private Float score;

    private String deviceHash;

    private int status;

    private String signatureId;

    private boolean success;

    private boolean failed;

    private Map<String, DeviceInfo> notApproved;

}
