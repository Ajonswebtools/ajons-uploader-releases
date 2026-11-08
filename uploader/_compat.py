try:
    from security_redaction import redact_text
except Exception:
    try:
        from uploader.security_redaction import redact_text
    except Exception:
        def redact_text(s): return s
