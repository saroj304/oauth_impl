package com.nchl.authserver.authorization_server.service.impl;

import com.nchl.authserver.authorization_server.model.dto.customer.CustomerDetails;
import com.nchl.authserver.authorization_server.repo.customer.ICustomerDao;
import com.nchl.authserver.authorization_server.service.ICustomerDetailService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
@AllArgsConstructor
@Slf4j
public class CustomerDetailServiceImpl implements ICustomerDetailService {
private final ICustomerDao customerDao;
    @Override
    public CustomerDetails getCustomerDetail(String custId) {
        log.info("Finding customer by customer ID:: {}", custId);
        String sanitizedUserId = StringUtils.trimAllWhitespace(custId);

          return customerDao.findCustomerDetailsByCustomerId(sanitizedUserId).get();

    }
}
