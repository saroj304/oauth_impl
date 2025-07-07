package com.nchl.authserver.authorization_server.service;

import com.nchl.authserver.authorization_server.model.dto.customer.CustomerDetails;

public interface ICustomerDetailService {
    CustomerDetails getCustomerDetail(String custId);
}
