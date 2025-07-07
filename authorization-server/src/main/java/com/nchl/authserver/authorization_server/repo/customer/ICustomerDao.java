package com.nchl.authserver.authorization_server.repo.customer;

import com.nchl.authserver.authorization_server.model.dto.customer.CustomerDetails;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;


public interface ICustomerDao {

    Optional<CustomerDetails> findCustomerDetailsByCustomerId(@Param("email") String email);

}
