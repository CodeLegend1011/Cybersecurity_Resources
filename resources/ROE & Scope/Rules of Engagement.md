# Rules of Engagement and Scoping

Penetration testing and security assessments require careful planning to ensure that the tests are conducted safely and effectively. The **Rules of Engagement** (RoE) serve as a formal agreement that defines the boundaries, goals, and limits of the testing process. This section outlines the key elements of RoE and provides insights into scoping the assessment of various APIs.

## Rules of Engagement (RoE)

The **Rules of Engagement** outline key parameters and restrictions for the penetration testing process. This ensures mutual understanding between the testing team and the organization being assessed. 

Below is a table that summarizes important elements of RoE with examples.

| **Rule of Engagement Element**                                  | **Example**                                                                                             |
|-----------------------------------------------------------------|---------------------------------------------------------------------------------------------------------|
| **Testing timeline**                                             | Three weeks, as specified in a Gantt chart                                                              |
| **Location of the testing**                                      | Company's headquarters in Raleigh, North Carolina                                                       |
| **Time window of the testing (times of day)**                    | 9:00 a.m. to 5:00 p.m. EST                                                                              |
| **Preferred method of communication**                            | Final report and weekly status update meetings                                                          |
| **Security controls that could potentially detect or prevent testing** | Intrusion prevention systems (IPSs), firewalls, data loss prevention (DLP) systems                       |
| **IP addresses or networks from which testing will originate**   | 10.10.1.0/24, 192.168.65.66, 10.20.15.123                                                               |
| **Types of allowed or disallowed tests**                         | Testing only web applications (app1.secretcorp.org and app2.secretcorp.org). No social engineering attacks are allowed. SQL injection attacks are only allowed in the development and staging environments at: <br> - app1-dev.secretcorp.org <br> - app1-stage.secretcorp.org <br> - app2-dev.secretcorp.org <br> - app2-stage.secretcorp.org |

### Key Elements of Rules of Engagement

1. **Testing Timeline**  
   The testing period, its start and end dates, and any expected deadlines for reporting or interim updates must be clearly defined. For example, testing may be scheduled for three weeks, with updates provided weekly.

2. **Location of Testing**  
   The geographical location from where testing will be conducted. Physical proximity may be required depending on the test, e.g., on-site vs. remote testing.

3. **Time Window for Testing**  
   The hours during which the testing will occur (e.g., during regular business hours or after hours). These restrictions ensure minimal disruption to business operations.

4. **Communication**  
   Preferred methods of communication, including how results will be shared (e.g., weekly meetings, email reports). Security of the communication method is important.

5. **Security Controls**  
   Identifying systems that may block, log, or disrupt penetration testing (such as firewalls, intrusion detection/prevention systems, or data loss prevention systems).

6. **Testing Origination Networks**  
   Defining which IP addresses or networks the testers will use to conduct their assessments. This ensures the organization can whitelist these ranges in their systems.

7. **Allowed/Disallowed Tests**  
   Which tests are permitted during the engagement and which are forbidden, based on the scope. For instance, social engineering might be excluded from the engagement to avoid misleading employees.

---

## Conclusion

Understanding the **Rules of Engagement** and **Scoping** is crucial for a comprehensive and effective penetration testing effort. This document outlined key elements to consider when drafting RoE and how to scope testing for various APIs, ensuring you cover all bases to minimize risks and maximize coverage during security assessments.

---

