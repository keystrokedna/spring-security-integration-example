package com.keystrokedna.examples.spring;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DeviceInfo {

    private String title;

    private String ipAddress;

    private String country;

    private String region;

    private String city;

    private Date date;

}
