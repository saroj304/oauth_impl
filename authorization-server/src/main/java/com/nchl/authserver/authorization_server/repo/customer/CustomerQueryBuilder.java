package com.nchl.authserver.authorization_server.repo.customer;

public class CustomerQueryBuilder {
   public static  String fetchCustomerDetailsByCustomerId = """
    SELECT 
        c.cust_id,
        c.cust_name,
        c.email_id,
        c.virtual_private_address,
        c.role_code
    FROM dmbs_customer_details_table c
    WHERE c.cust_id = :custID
""";

}
