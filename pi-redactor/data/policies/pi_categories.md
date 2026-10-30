# Personal Information Classification Standard (synthetic sample policy)

## Purpose and scope
This standard defines which data elements are Personal Information (PI) for the purpose of document
redaction. It applies to all documents shared through enterprise collaboration platforms (Microsoft Teams,
SharePoint, OneDrive, email) including Word, Excel, PowerPoint, PDF, text and email content.

## Tier 1 - Highly sensitive identifiers (always redact)
Government and financial identifiers that enable identity theft or fraud must always be redacted before
any document leaves the owning team: Aadhaar numbers, PAN numbers, passport numbers, US Social Security
Numbers, national insurance / NHS numbers, driving licence numbers, credit and debit card numbers, bank
account numbers and IBANs. Tier 1 items may not be kept even if the reviewer believes the recipient is
authorised; share the original through the secure vault instead.

## Tier 2 - Direct contact identifiers (redact by default)
Full names of private individuals, personal and work email addresses, phone and mobile numbers, residential
and postal addresses, and employee IDs. A reviewer may keep a Tier 2 item only when the recipient is inside
the same legal entity and has a business need, and must record the reason in the review step.
Names of public figures or company signatories acting in an official capacity in a published contract
may be kept.

## Tier 3 - Indirect and quasi-identifiers (review case by case)
Dates of birth, IP addresses, device IDs, job title combined with location, salary, health information,
and any combination of attributes that could single out an individual. The automated scanner flags these
with lower confidence; the human reviewer decides. Health, biometric, caste, religion and sexual orientation
data is Sensitive Personal Data and must be redacted.

## User-defined sensitive keywords
Business units may register sensitive keywords (for example confidential project code names, client code
names, or internal system names). These are treated as Tier 2 and redacted by default. Keywords are
configured per redaction job and are not stored after the job completes.

## Not PI
Company names, product names, generic role names without a person ("the Project Manager"), public office
addresses of the organisation, and fully aggregated statistics that cannot identify an individual are not PI.
