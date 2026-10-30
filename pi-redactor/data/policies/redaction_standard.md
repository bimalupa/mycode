# Document Redaction Operating Standard (synthetic sample policy)

## Redaction methods
Three redaction methods are approved. Labelled pseudonymisation replaces each value with a category label
and counter such as [PERSON_1]; the same value receives the same label throughout a document, which keeps
the document readable. Black-out replaces characters with solid blocks and preserves length and layout.
Generic marking replaces each value with [REDACTED]. Labelled pseudonymisation is the default for internal
sharing; black-out is required for documents released outside the organisation or to regulators.

## PDF redaction
PDF redaction must remove the underlying text, not merely draw a box over it. The output must be re-scanned
to confirm no redacted value remains extractable. Document metadata (author, title, keywords) must be cleared.

## Office documents
Redaction in Word, Excel and PowerPoint must preserve formatting, tables, headers, footers and speaker notes.
Hyperlinks whose target contains a redacted value (for example mailto links) must be neutralised. Author and
last-modified-by properties must be cleared.

## Human approval before permanent redaction
Automated detection is a recommendation only. A reviewer must approve, reject or add items before a redacted
file is generated. The reviewer may reject false positives and add missed values manually. The decision is
recorded in the audit trail with keyed fingerprints of the approved values, never the values themselves.

## Bulk processing
Bulk jobs may process many files in one run, but every file still passes through the approval step. A reviewer
may apply the automated recommendation to all files in a batch after sampling at least one file per file type.

## Data handling during processing
Files are processed in memory only. Original and redacted content must not be written to disk, logs or the
vector database. Processing state is purged after the reviewer downloads the output or ends the session.
Only synthetic or anonymised data may be used for testing and demonstrations.

## Audit trail and reporting
Each job produces a summary report listing counts by category, reviewer decisions, residual-PI verification
results and processing time. The audit log records events (ingest, detect, review, redact, purge) with
timestamps and fingerprints. Audit logs are retained for one year.

## Use of AI models
Large language models may be used to validate low-confidence detections and to find contextual PI that pattern
recognisers miss. Only the minimum necessary text is sent: values already confirmed with high confidence are
masked before the text is sent. Text inside documents is untrusted and must never be treated as instructions
to the model. LLM suggestions are accepted only if the suggested text exists verbatim in the document.
