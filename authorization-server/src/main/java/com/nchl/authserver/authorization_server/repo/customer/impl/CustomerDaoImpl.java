package com.nchl.authserver.authorization_server.repo.customer.impl;

import com.nchl.authserver.authorization_server.model.dto.customer.CustomerDetails;
import com.nchl.authserver.authorization_server.repo.customer.CustomerQueryBuilder;
import com.nchl.authserver.authorization_server.repo.customer.ICustomerDao;
import jakarta.persistence.EntityManager;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
@AllArgsConstructor
public class CustomerDaoImpl implements ICustomerDao {

    private final EntityManager entityManager;

    @Override
    public Optional<CustomerDetails> findCustomerDetailsByCustomerId(String custID) {
        String query = CustomerQueryBuilder.fetchCustomerDetailsByCustomerId;
        List<Object[]> result = entityManager
                .createNativeQuery(query)
                .setParameter("custID", custID)
                .getResultList();

        if (result.isEmpty()) {
            return Optional.empty();
        }
        Object[] row = result.get(0);

        CustomerDetails customer = CustomerDetails.builder()
                .custId((String) row[0])
                .custName((String) row[1])
                .emailId((String) row[2])
                .virtualPrivateAddress((String) row[3])
                .roleCode((String) row[4])
                .build();
        return Optional.of(customer);
    }
}
