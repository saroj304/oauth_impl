package com.nchl.authserver.authorization_server.model.dto.customer;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;


@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
public class CustomerRole implements Serializable {

    private static final long serialVersionUID = -963138547220347407L;

    private Long id;


    private String code;

    private String name;


    private String description;


    private Boolean enabled;

    private Boolean delFlag;

    private String createdBy;

    private LocalDateTime createdTime;

    private String updatedBy;

    private LocalDateTime updatedTime;

    private String entityCreationFlag;

    private String entityCreatedBy;

    private LocalDateTime entityCreatedTime;
}


