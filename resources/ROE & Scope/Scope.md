# Scope and Validation of Scope

## Key Questions for Scope Validation

1. **What is the entity’s or individual’s need for the report?**  
   Understanding the rationale for the report helps in tailoring the findings to meet specific objectives.

2. **What is the position of the individual who will be the primary recipient of the report within the organization?**  
   This ensures the report is presented at the appropriate level of technical detail.

3. **What is the main purpose and goal of the penetration testing engagement and ultimately the purpose of the report?**  
   Clear objectives will guide the focus of the testing effort and reporting.

4. **What is the individual’s or business unit’s responsibility and authority to make decisions based on your findings?**  
   Knowing who can act on the report’s recommendations is crucial for ensuring accountability.

5. **Who will the report be addressed to?**  
   Identify the key stakeholders (e.g., ISM, CISO, CIO, CTO) who will receive the report.

6. **Who will have access to the report?**  
   Determine the access controls for sensitive information contained within the report, ensuring that only authorized individuals have access.

7. **How will you maintain open communication with the clients and stakeholders?**  
   Establish clear lines of communication to facilitate ongoing discussions throughout the engagement.

---

## Communication and Interaction

### Contact Information for Stakeholders
- Document all relevant stakeholders' contact information to ensure effective communication.

### Communication Methods
- Specify how you will communicate with the stakeholders (e.g., email, phone calls, meetings).

### Frequency of Interaction
- Determine how often you need to interact with the stakeholders (e.g., daily, weekly, bi-weekly).

### Emergency Contacts
- Identify individuals you can contact at any time in case of emergencies.

---

## Addressing Common Questions

1. **How do I explain the overall cost of penetration testing to my boss?**  
   Break down the costs associated with resources, time, and the potential risks mitigated through testing.

2. **Why do we need penetration testing if we have all these security technical and non-technical controls in place?**  
   Emphasize that penetration testing identifies weaknesses that may be overlooked by existing controls.

3. **How do I build in penetration testing as a success factor?**  
   Highlight success stories and improvements made based on previous penetration testing engagements.

4. **Can I do it myself?**  
   Discuss the benefits of engaging professional services for a comprehensive assessment.

5. **How do I calculate the ROI for the penetration testing engagement?**  
   Analyze the cost savings from prevented incidents versus the investment made in testing.

---

## Stakeholder and Emergency Contact Information

It is essential to gather detailed information about stakeholders involved in the penetration testing engagement. Below is a template for documenting primary stakeholders and emergency contacts.

![Stakeholder and Emergency Contact Card Example](https://github.com/user-attachments/assets/25c161d0-4933-41a0-b266-0636fa7e40e5)

---

## Tester Considerations

1. **How do I account for all items of the penetration testing engagement to avoid going over budget?**  
   Create a detailed budget plan that outlines expected costs and contingencies.

2. **How do I do pricing?**  
   Base pricing on factors such as project scope, resource allocation, and time estimates.

3. **How can I clearly show ROI to my client?**  
   Use metrics and examples to illustrate risk reductions and enhanced security posture resulting from the engagement.

---

## API Testing

When performing penetration testing, API endpoints represent a critical attack vector. Scoping APIs requires detailed planning around the specific technologies in use and their interactions. Below are examples of different types of APIs and how they should be scoped.

### 1. **SOAP (Simple Object Access Protocol)**
- **Description:** SOAP is a protocol for exchanging structured information in web services. It relies on XML for message formatting.
- **Scoping Considerations:**
  - Analyze WSDL (Web Services Description Language) files for vulnerabilities.
  - Test for improper input validation in SOAP requests.
  - Test for XML external entity (XXE) attacks and data leakage.
  - Ensure proper authentication and authorization in API calls.
  - **SOAP**: [W3C SOAP Specification](https://www.w3.org/TR/soap/)

### 2. **Swagger (OpenAPI)**
- **Description:** Swagger/OpenAPI is a framework for defining and documenting RESTful APIs.
- **Scoping Considerations:**
  - Review the Swagger JSON or YAML definition for exposed endpoints.
  - Test for insecure HTTP methods (e.g., PUT, DELETE).
  - Test for improper access control on sensitive endpoints.
  - Ensure API authentication (e.g., OAuth) is secure.
  - **Swagger**: [Swagger Official Site](https://swagger.io/)
  -  [OpenAPI Specification GitHub Repository](https://github.com/OAI/OpenAPI-Specification)

### 3. **GraphQL**
- **Description:** GraphQL is a query language for APIs, allowing clients to request specific data from the server.
- **Scoping Considerations:**
  - Test for insecure queries that may allow unauthorized data retrieval.
  - Ensure there are limits on query depth and complexity to avoid denial-of-service attacks.
  - Check for broken authentication and authorization mechanisms.
  - Test for introspection leaks that expose sensitive schema details.
  - **GraphQL**: [GraphQL Learn](https://graphql.org/learn/)

### 4. **WADL (Web Application Description Language)**
- **Description:** WADL is used for describing RESTful services, much like WSDL for SOAP services.
- **Scoping Considerations:**
  - Review the WADL for exposed methods and their security configurations.
  - Test for injection vulnerabilities in REST endpoints.
  - Ensure the secure transmission of data over HTTPs.
  - Verify the proper implementation of API authentication.
  - **WADL**: [W3C WADL Submission](https://www.w3.org/submissions/wadl/)

### 5. **WSDL (Web Services Description Language)**
- **Description:** WSDL describes web service functionality and the associated requests/responses.
- **Scoping Considerations:**
  - Test for XML injection and XXE vulnerabilities.
  - Verify the robustness of error handling and input validation.
  - Ensure that the web service follows secure SOAP message exchanges.
  - Check for misconfigurations that may expose sensitive information.
  - **WSDL**: [W3C WSDL 2.0 Primer](https://www.w3.org/TR/wsdl20-primer/)

---

## Strategy: Unknown vs. Known Environment Testing

- **Unknown Environment Testing:**  
  Involves testing an environment where the tester has no prior knowledge of the system, its architecture, or its security measures. This approach simulates a real-world attack scenario, allowing for an unbiased assessment of security vulnerabilities.

- **Known Environment Testing:**  
  Involves testing an environment where the tester has prior knowledge of the system, including architecture and security controls. This type of testing can provide insights into how effective existing security measures are and can help in validating compliance with security policies and regulations.

---

## Key Features

- **Stakeholder and Emergency Contact Section:** Provides a structured template for gathering essential contact information.
- **Scope Validation Questions:** Addresses critical questions to guide the scope of the penetration testing engagement.
- **Communication and Interaction:** Highlights the importance of maintaining effective communication with stakeholders.
- **Common Questions and Tester Considerations:** Offers insights into frequently asked questions regarding penetration testing and ROI.
- **Strategy Section:** Differentiates between unknown and known environment testing strategies.
