# Team Information

Abdul Nafay 22i-1605

Hasham Hassan 22i-1617

Muhammad Abdullah 22i-1721

Hassan Ali 22i-7423

Faiq Imtiaz 22i-1581

# Problem Statement

Organizations frequently need to share datasets for purposes such as research, software development, or analytics.

However, these datasets often contain sensitive information such as names, addresses, identification numbers, or financial details.

If such information is shared without protection, it can lead to privacy violations, regulatory non-compliance, and even identity theft.

Traditional methods of hiding sensitive data, such as simple removal of identifiers, are not always sufficient because attackers can sometimes re-identify individuals through indirect information.

This makes data anonymization and masking a critical security measure.

The problem is therefore to design a system that allows data to be safely shared while preserving its analytical value.

# Objectives of the Project

The objective of this project is to design a tool that can mask or anonymize sensitive data in a dataset before it is shared outside a secure environment.

The tool should preserve the usefulness of the dataset for analysis while ensuring that no sensitive personal information can be reconstructed.

Another goal is to make the system easy to use for non-technical users who may need to prepare datasets quickly.

Finally, the project aims to support multiple anonymization techniques such as substitution, shuffling, generalization, and differential privacy to address different use cases.

# Proposed Solution

The proposed solution is to build a standalone software tool that allows users to upload structured datasets such as CSV or Excel files.

The system will then identify columns containing sensitive information, either through predefined rules or user input, and apply anonymization techniques.

For example, names could be replaced with pseudonyms, credit card numbers could be masked with random digits, and birthdates could be generalized to age ranges.

The tool will also include an option for irreversible anonymization where data is fully de-identified so that it cannot be linked back to an individual.

The final output will be a secure dataset that retains analytical properties without exposing sensitive details.

# Methodology

The project will follow the Secure Software Development Lifecycle.

During the requirements phase, we will study existing anonymization techniques and identify which are most useful in practical scenarios.

In the design phase, we will model the workflow for data ingestion, identification of sensitive fields, and application of anonymization algorithms.

We will also perform threat modeling to anticipate possible re-identification attempts.

The implementation phase will focus on secure coding practices while building the tool in Python.

Testing will include unit tests for anonymization algorithms, integration tests for data pipelines, and validation tests to confirm that anonymized datasets still retain usability.

In deployment, the system will include logging and access control to ensure that only authorized users can process datasets.

# Tools and Technologies

The tool will be implemented in Python.

For data handling, we will use the Pandas library, which supports efficient operations on structured data.

For anonymization algorithms, we will use libraries such as Faker for pseudonym generation and Scikit-learn for data shuffling and transformations.

Cryptographic operations such as hashing will be handled using the PyCryptodome library.

The user interface will be built using Flask for a simple web-based application, and all processing will take place locally to ensure that data does not leave the secure environment.

For exporting results, the tool will support CSV and Excel formats using the OpenPyXL library.

# Expected Deliverables

The deliverables for this project will include the working Data Masking and Anonymization Tool, complete documentation explaining the anonymization techniques, and a report on testing and evaluation.

We will also prepare a presentation to demonstrate the usefulness of the tool and to explain how it can help organizations meet compliance requirements such as GDPR and HIPAA.

The final deliverable will be a user manual that explains step-by-step how to use the system to anonymize a dataset.

# Timeline

The project will take approximately thirteen weeks.

- Weeks one and two will focus on studying anonymization methods and compliance requirements.  
- Weeks three to five will involve design of the system workflow and database structures.  
- Implementation will take place in weeks six through ten, with anonymization algorithms and user interface development.  
- Testing will be carried out in weeks eleven and twelve, including validation with different datasets  
- The final week will be used for preparing documentation and a presentation.

# References

This project will be guided by well-known privacy frameworks such as the General Data Protection Regulation (GDPR) and the Health Insurance Portability and Accountability Act (HIPAA).

It will also draw on research papers in privacy-preserving data publishing and standards such as the NIST Privacy Framework.

Open-source libraries and anonymization guidelines from the wider research community will serve as supporting references.
