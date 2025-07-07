package com.nchl.authserver.authorization_server.model.dto.customer;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.nchl.authserver.authorization_server.model.enums.EnrollType;
import com.nchl.authserver.authorization_server.model.enums.UserStatus;
import com.nchl.authserver.authorization_server.security.config.CryptoConverter;
import io.micrometer.common.util.StringUtils;
import jakarta.persistence.*;
import lombok.*;

import org.hibernate.annotations.DynamicUpdate;
import org.springframework.data.domain.Persistable;

import java.io.Serializable;
import java.time.LocalDate;
import java.time.LocalDateTime;

//@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@DynamicUpdate
//@Table(name = "dmbs_customer_details_table")
public class CustomerDetails implements Serializable, Persistable<String> {

    private static final long serialVersionUID = -963138547220347406L;

    //    @Id
    private String custId;

    private String custName;

    //    @Convert(converter = CryptoConverter.class)
    private String virtualPrivateAddress;

    @JsonIgnore
    private String password;

    @Convert(converter = CryptoConverter.class)
    private String emailId;

    @Convert(converter = CryptoConverter.class)
    private String mobileNo;

    @Convert(converter = CryptoConverter.class)
    private String cifId;


    private CustomerRole role;

    private String roleCode;

    private Integer accountNonExpired;

    private Integer accountNonLocked;

    private Integer credentialNonExpired;

    private Integer enabled;

    private LocalDateTime pwdLchgDate;

    @JsonIgnore
    private String secretKey;

    private String isFirstLogin;

    private String txnPwd;

    private LocalDateTime tpwdLchgDate;

    private Integer tpwdNonLocked;

    private String loginStatus;

    private String gender;

    private String referalCode;

    private Integer userInState;

    private String rcreUserId;

    private LocalDateTime rcreTime;

    private String lchgUserId;

    private LocalDateTime lchgTime;

    private String entityCreFlg;

    private String entityCreUserId;

    private LocalDateTime entityCreTime;

    private LocalDate dateOfBirth;

    @Enumerated(EnumType.STRING)
    private UserStatus userStatus;

    @Enumerated(EnumType.STRING)
    private EnrollType enrollType;

    private String subsProfileCode;

    private String enrolledByBranch;

    private Integer enrolledByBrachFkey;

    //new
    private String staffBranchId;

    @Override
    public String getId() {
        return this.custId;
    }

    @Override
    public boolean isNew() {
        return StringUtils.isBlank(this.custId);
    }
}
