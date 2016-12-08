class SAMSCriticalError(Exception):
    """SAMS encounted a critical error."""
    pass

class SAMSStartupError(SAMSCriticalError):
    """Error starting up SAMS."""
    pass

class SAMSDatabaseError(SAMSCriticalError):
    """SAMS database error."""
    pass

class SAMSOperationalError(Exception):
    """SAMS operation error."""
    pass

class SAMSPostMasterConnectError(SAMSOperationalError):
    """Error starting up SAMS."""
    pass

class SAMSPostMasterLoginError(SAMSOperationalError):
    """Error starting up SAMS."""
    pass

class SAMSPostMasterFetchError(SAMSOperationalError):
    """Error starting up SAMS."""
    pass

class SAMSAnalysisError(SAMSOperationalError):
    """Error starting up SAMS."""
    pass
