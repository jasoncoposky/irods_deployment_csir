
DEFAULT_RESOURCE_NAME { "PTA_Prov0" }

acSetRescSchemeForCreate {
    msiSetDefaultResc(DEFAULT_RESOURCE_NAME,"preferred");
}

acSetRescSchemeForRepl {
    msiSetDefaultResc(DEFAULT_RESOURCE_NAME,"preferred");
}

